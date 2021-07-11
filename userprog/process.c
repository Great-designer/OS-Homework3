#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "threads/malloc.h"
#include "vm/page.h"
#include "vm/frame.h"

static thread_func start_process NO_RETURN;
//static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool load(const char *cmd_line,void (**eip) (void),void **esp);

//在调用线程中的process_execute（）和新调用线程中的start_process（）之间共享的数据结构。
struct exec_info 
{
	const char *file_name;//要加载的程序
	struct semaphore load_done;//加载完成时“向上”
	struct wait_status *wait_status;//子进程
	bool success;//程序成功加载
};

//启动一个新线程，运行从FILENAME加载的用户程序
//在process\u execute（）返回之前，可能会安排新线程（甚至可能退出）
//返回新进程的线程id，如果无法创建线程，则返回TID\U错误
tid_t process_execute(const char *file_name) 
{
//	char *fn_copy;
//	tid_t tid;
////复制文件名
////否则，调用者和load（）之间就会发生竞争
//	fn_copy=palloc_get_page(0);
//	if(fn_copy == NULL)
//	{
//		return TID_ERROR;
//	}
//	strlcpy(fn_copy,file_name,PGSIZE);
////创建一个新线程来执行文件名
//	tid=thread_create(file_name,PRI_DEFAULT,start_process,fn_copy);
//	if(tid == TID_ERROR)
//	{
//		palloc_free_page(fn_copy); 
//	}
//	return tid;
	struct exec_info exec;
	char thread_name[16];
	char *save_ptr;
	tid_t tid;
//初始化执行信息
	exec.file_name=file_name;
	sema_init(&exec.load_done,0);
//创建一个新线程来执行文件名
	strlcpy(thread_name,file_name,sizeof thread_name);
	strtok_r(thread_name," ",&save_ptr);
	tid=thread_create(thread_name,PRI_DEFAULT,start_process,&exec);
	if(tid!=TID_ERROR)
	{
		sema_down(&exec.load_done);
		if(exec.success)
		{
			list_push_back(&thread_current()->children,&exec.wait_status->elem);
		}
		else
		{
			tid=TID_ERROR;
		}
	}
	return tid;
}

//static void start_process(void *file_name_)
//{
//	char *file_name=file_name_;
//	struct intr_frame if_;
//	bool success;
////初始化中断帧并加载可执行文件
//	memset (&if_, 0, sizeof if_);
//	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
//	if_.cs = SEL_UCSEG;
//	if_.eflags = FLAG_IF | FLAG_MBS;
//	success = load (file_name, &if_.eip, &if_.esp);
////如果加载失败，请退出
//	palloc_free_page (file_name);
//	if (!success)
//	{
//		thread_exit ();
//	}
////通过模拟中断返回来启动用户进程，由intr_exit实现（在threads/intr stubs.S中）。
////因为intr_exit以“struct intr_frame”的形式接受堆栈上的所有参数，所以我们只需将堆栈指针（%esp）指向堆栈帧并跳转到它。
//	asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
//	NOT_REACHED ();
//}

//加载用户进程并使其开始运行的线程函数
static void start_process(void *exec_)
{
	struct exec_info *exec = exec_;
	struct intr_frame if_;
	bool success;
//初始化中断帧并加载可执行文件
	memset (&if_, 0, sizeof if_);
	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
	if_.cs = SEL_UCSEG;
	if_.eflags = FLAG_IF | FLAG_MBS;
	success = load (exec->file_name, &if_.eip, &if_.esp);
//分配等待状态
	if(success)
    {
		exec->wait_status = thread_current ()->wait_status= malloc (sizeof *exec->wait_status);
		success = exec->wait_status != NULL; 
	}
//初始化等待状态
	if (success) 
	{
		lock_init (&exec->wait_status->lock);
		exec->wait_status->ref_cnt = 2;
		exec->wait_status->tid = thread_current ()->tid;
		sema_init (&exec->wait_status->dead, 0);
	}
//通知父线程并清理
	exec->success = success;
	sema_up (&exec->load_done);
	if (!success)
	{
		thread_exit ();
	}
//通过模拟中断返回来启动用户进程，由intr_exit实现（在threads/intr stubs.S中）
//因为intr_exit以“struct intr_frame”的形式接受堆栈上的所有参数，所以我们只需将堆栈指针（%esp）指向堆栈帧并跳转到它
	asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
	NOT_REACHED ();
}

//释放对CS的一个引用，如果它现在未被引用，则释放它。
static void release_child(struct wait_status *cs) 
{
	int new_ref_cnt;
	lock_acquire (&cs->lock);
	new_ref_cnt = --cs->ref_cnt;
	lock_release (&cs->lock);
	if (new_ref_cnt == 0)
	{
		free (cs);
	}
}

//等待线程TID结束并返回其退出状态。
//如果它被内核终止（即由于异常而终止），则返回-1。
//如果TID无效，或者它不是调用进程的子进程，或者如果已经为给定的TID成功调用了process_wait（），则立即返回-1，而不等待。
//int process_wait (tid_t child_tid UNUSED) 
//{
//	return -1;
//}

//等待线程TID结束并返回其退出状态。
//如果它被内核终止（即由于异常而终止），则返回-1。
//如果TID无效，或者它不是调用进程的子进程，或者如果已经为给定的TID成功调用了process_wait（），则立即返回-1，而不等待。
int process_wait(tid_t child_tid) 
{
	struct thread *cur=thread_current();
	struct list_elem *e;
	for(e=list_begin(&cur->children);e!=list_end(&cur->children);e=list_next(e)) 
	{
		struct wait_status *cs=list_entry(e,struct wait_status,elem);
		if(cs->tid==child_tid)
		{
			int exit_code;
			list_remove(e);
			sema_down(&cs->dead);
			exit_code=cs->exit_code;
			release_child(cs);
			return exit_code;
		}
	}
	return -1;
}

//释放当前进程的资源
void process_exit(void)
{
	struct thread *cur=thread_current();
	uint32_t *pd;

	struct list_elem *e,*next;
	printf("%s: exit(%d)\n",cur->name,cur->exit_code);
//通知父进程 
	if(cur->wait_status!=NULL) 
	{
		struct wait_status *cs = cur->wait_status;
		cs->exit_code = cur->exit_code;
		sema_up (&cs->dead);
		release_child (cs);
    }
//释放输入子列表
	for(e=list_begin(&cur->children);e!=list_end(&cur->children);e=next) 
	{
		struct wait_status *cs = list_entry (e, struct wait_status, elem);
		next = list_remove (e);
		release_child (cs);
	}
//销毁页哈希表
	page_exit();
// 关闭可执行文件（并允许写入）
	file_close(cur->bin_file);

//销毁当前进程的页面目录并切换回仅内核的页面目录
	pd=cur->pagedir;
	if(pd!=NULL) 
	{
//这里的正确排序至关重要。
//在切换页面目录之前，我们必须将cur->pagedir设置为NULL，这样计时器中断就不能切换回进程页面目录。
//在销毁进程的页目录之前，我们必须激活基页目录，否则我们的活动页目录将是一个已被释放（并被清除）的目录。
		cur->pagedir=NULL;
		pagedir_activate(NULL);
		pagedir_destroy(pd);
	}
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

//static bool setup_stack(void **esp);
static bool setup_stack(const char *cmd_line,void **esp);

static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

//从文件名加载ELF可执行文件到当前线程
//将可执行文件的入口点存储到*EIP中，并将其初始堆栈指针存储到*ESP中
//如果成功，则返回true，否则返回false
//bool load(const char *file_name,void (**eip)(void),void **esp) 
//{
//	struct thread *t = thread_current ();
//	struct Elf32_Ehdr ehdr;
//	struct file *file = NULL;
//	off_t file_ofs;
//	bool success = false;
//	int i;
////分配并激活页面目录
//	t->pagedir = pagedir_create ();
//	if (t->pagedir == NULL)
//	{
//		goto done;
//	}
//	process_activate ();
////打开可执行文件
//	file = filesys_open (file_name);
//	if (file == NULL) 
//	{
//		printf ("load: %s: open failed\n", file_name);
//		goto done; 
//    }
////读取并验证可执行头
//	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
//      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
//      || ehdr.e_type != 2
//      || ehdr.e_machine != 3
//      || ehdr.e_version != 1
//      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
//      || ehdr.e_phnum > 1024) 
//	{
//		printf ("load: %s: error loading executable\n", file_name);
//		goto done; 
//    }
////读取程序标题
//	file_ofs = ehdr.e_phoff;
//	for (i = 0; i < ehdr.e_phnum; i++) 
//	{
//		struct Elf32_Phdr phdr;
//		if (file_ofs < 0 || file_ofs > file_length (file))
//		{
//			goto done;
//		}
//		file_seek (file, file_ofs);
//		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
//		{
//			goto done;
//		}
//		file_ofs += sizeof phdr;
//		switch (phdr.p_type) 
//		{
//		case PT_NULL:
//		case PT_NOTE:
//		case PT_PHDR:
//		case PT_STACK:
//		default:
////忽略此段
//			break;
//		case PT_DYNAMIC:
//		case PT_INTERP:
//		case PT_SHLIB:
//			goto done;
//		case PT_LOAD:
//			if(validate_segment (&phdr, file)) 
//			{
//				bool writable = (phdr.p_flags & PF_W) != 0;
//				uint32_t file_page = phdr.p_offset & ~PGMASK;
//				uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
//				uint32_t page_offset = phdr.p_vaddr & PGMASK;
//				uint32_t read_bytes, zero_bytes;
//				if (phdr.p_filesz > 0)
//				{
////正常段
////从磁盘上读取初始部分，其余部分归零
//					read_bytes=page_offset+phdr.p_filesz;
//					zero_bytes=(ROUND_UP(page_offset+phdr.p_memsz,PGSIZE)-read_bytes);
//				}
//				else 
//				{
////完全零
////不要从磁盘上读取任何内容
//					read_bytes = 0;
//					zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
//				}
//				if(!load_segment (file, file_page, (void *) mem_page,read_bytes, zero_bytes, writable))
//				{
//					goto done;
//				}
//			}
//			else
//			{
//				goto done;
//			}
//			break;
//		}
//	}
////设置堆栈
//	if (!setup_stack (esp))
//	{
//		goto done;
//	}
////起始地址
//	*eip = (void (*) (void)) ehdr.e_entry;
//	success = true;
//done:
////不管装载成功与否，我们都会到达这里
//	file_close (file);
//	return success;
//}


//从文件名加载ELF可执行文件到当前线程
//将可执行文件的入口点存储到*EIP中，并将其初始堆栈指针存储到*ESP中
//如果成功，则返回true，否则返回false
bool load(const char *cmd_line,void (**eip) (void),void **esp) 
{
	struct thread *t = thread_current ();
	char file_name[NAME_MAX + 2];
	struct Elf32_Ehdr ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	char *cp;
	int i;
//分配并激活页面目录
	t->pagedir = pagedir_create ();
	if (t->pagedir == NULL)
	{
		goto done;
	}
	process_activate ();
//创建页哈希表
	t->pages = malloc (sizeof *t->pages);
	if (t->pages == NULL)
	{
		goto done;
	}
	hash_init (t->pages, page_hash, page_less, NULL);
//从命令行提取文件名
	while (*cmd_line == ' ')
	{
		cmd_line++;
	}
	strlcpy (file_name, cmd_line, sizeof file_name);
	cp = strchr (file_name, ' ');
	if (cp != NULL)
	{
		*cp = '\0';
	}
//打开可执行文件
	t->bin_file = file = filesys_open (file_name);
	if (file == NULL) 
	{
		printf ("load: %s: open failed\n", file_name);
		goto done; 
	}
	file_deny_write (t->bin_file);
//读取并验证可执行头
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
	{
		printf ("load: %s: error loading executable\n", file_name);
		goto done; 
	}
//读取程序标题
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) 
	{
		struct Elf32_Phdr phdr;
		if (file_ofs < 0 || file_ofs > file_length (file))
		{
			goto done;
		}
		file_seek (file, file_ofs);
		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
		{
			goto done;
		}
		file_ofs += sizeof phdr;
		switch (phdr.p_type) 
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
//忽略此段
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment (&phdr, file)) 
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint32_t file_page = phdr.p_offset & ~PGMASK;
				uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint32_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
//正常段
//从磁盘上读取初始部分，其余部分归零
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)- read_bytes);
				}
				else 
				{
//完全零
//不要从磁盘上读取任何内容
					read_bytes = 0;
					zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment (file, file_page, (void *) mem_page,read_bytes, zero_bytes, writable))
				{
					goto done;
				}
			}
			else
			{
				goto done;
			}
			break;
		}
	}
//设置堆栈
	if (!setup_stack (cmd_line, esp))
	{
		goto done;
	}
//起始地址
	*eip = (void (*) (void)) ehdr.e_entry;
	success = true;
done:
//不管装载成功与否，我们都会到达这里
	return success;
}

/* load() helpers. */

//static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

//在地址升级时，从文件中偏移量OFS开始加载段。
//总共，初始化虚拟内存的READ_BYTES+ZERO_BYTES，如下所示：
//-必须从偏移量为OFS的文件读取升级时的读取字节字节
//-升级时的零字节字节+读字节必须为零
//如果writable为true，则此函数初始化的页必须可由用户进程写入，否则为只读
//如果成功，则返回true；如果发生内存分配错误或磁盘读取错误，则返回false
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);
//	file_seek(file,ofs);
//	while (read_bytes > 0 || zero_bytes > 0) 
//	{
////计算如何填写此页。
////我们将从文件中读取PAGE_read_BYTES字节，并将最终的PAGE_zero_BYTES字节归零
//		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
//		size_t page_zero_bytes = PGSIZE - page_read_bytes;
////得到一页内存 
//		uint8_t *kpage = palloc_get_page (PAL_USER);
//		if (kpage == NULL)
//		{
//			return false;
//		}
////加载此页
//		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
//		{
//			palloc_free_page (kpage);
//			return false; 
//		}
//		memset (kpage + page_read_bytes, 0, page_zero_bytes);
////将页面添加到进程的地址空间
//		if (!install_page (upage, kpage, writable)) 
//		{
//			palloc_free_page (kpage);
//			return false; 
//		}
////前进
//		read_bytes -= page_read_bytes;
//		zero_bytes -= page_zero_bytes;
//		upage += PGSIZE;
//	}
//	return true;
//}

	while (read_bytes > 0 || zero_bytes > 0) 
	{
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		struct page *p = page_allocate (upage, !writable);
		if (p == NULL)
		{
			return false;
		}
		if (page_read_bytes > 0) 
		{
			p->file = file;
			p->file_offset = ofs;
			p->file_bytes = page_read_bytes;
		}
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		ofs += page_read_bytes;
		upage += PGSIZE;
	}
	return true;
}

static void reverse(int argc,char **argv)//颠倒ARGV中指向char的ARGC指针的顺序
{
	for(;argc>1;argc-=2,argv++) 
	{
		char *tmp=argv[0];
		argv[0]=argv[argc-1];
		argv[argc-1]=tmp;
	}
}

//将BUF中的大小字节压入KPAGE中的堆栈，其页相对堆栈指针为*OFS，然后适当调整*OFS
//推送的字节四舍五入到32位边界
//如果成功，则返回指向新推送对象的指针
//失败时，返回空指针
static void *push(uint8_t *kpage,size_t *ofs,const void *buf,size_t size) 
{
	size_t padsize = ROUND_UP (size, sizeof (uint32_t));
	if (*ofs < padsize)
	{
		return NULL;
	}
	*ofs -= padsize;
	memcpy (kpage + *ofs + (padsize - size), buf, size);
	return kpage + *ofs + (padsize - size);
}

//在KPAGE中设置命令行参数，该参数将映射到用户空间中的UPAGE
//命令行参数取自命令行，用空格分隔
//将*ESP设置为进程的初始堆栈指针
static bool init_cmd_line(uint8_t *kpage, uint8_t *upage, const char *cmd_line,void **esp) 
{
	size_t ofs = PGSIZE;
	char *const null = NULL;
	char *cmd_line_copy;
	char *karg, *saveptr;
	int argc;
	char **argv;
//推送命令行字符串
	cmd_line_copy = push (kpage, &ofs, cmd_line, strlen (cmd_line) + 1);
	if (cmd_line_copy == NULL)
	{
		return false;
	}
	if (push (kpage, &ofs, &null, sizeof null) == NULL)
	{
		return false;
	}
//将命令行解析为参数并按相反的顺序推送它们
	argc = 0;
	for(karg=strtok_r(cmd_line_copy," ",&saveptr);karg!=NULL;karg=strtok_r(NULL," ",&saveptr))
	{
		void *uarg = upage + (karg - (char *) kpage);
		if (push (kpage, &ofs, &uarg, sizeof uarg) == NULL)
		{
			return false;
		}
		argc++;
	}
//颠倒命令行参数的顺序
	argv = (char **) (upage + ofs);
	reverse (argc, (char **) (kpage + ofs));
//按下argv，argc，“return address”
	if(push(kpage,&ofs,&argv,sizeof argv)==NULL||push(kpage,&ofs,&argc,sizeof argc)==NULL||push(kpage,&ofs,&null,sizeof null)==NULL)
	{
		return false;
	}
//设置初始堆栈指针
	*esp = upage + ofs;
	return true;
}

//通过在用户虚拟内存顶部映射一个归零的页面来创建一个最小的堆栈
//static bool setup_stack(void **esp) 
//{
//	uint8_t *kpage;
//	bool success = false;
//	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
//	if (kpage != NULL) 
//	{
//		success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
//		if (success)
//		{
//			*esp = PHYS_BASE;
//		}
//		else
//		{
//			palloc_free_page(kpage);
//		}
//	}
//	return success;
//}

//通过在用户虚拟内存顶部映射一个归零的页面来创建一个最小的堆栈
static bool setup_stack(const char *cmd_line,void **esp) 
{
	struct page *page=page_allocate(((uint8_t *)PHYS_BASE)-PGSIZE,false);
	if(page!=NULL) 
	{
		page->frame=frame_alloc_and_lock(page);
		if(page->frame!=NULL)
		{
			bool ok;
			page->read_only=false;
			page->private=false;
			ok=init_cmd_line(page->frame->base,page->addr,cmd_line,esp);
			frame_unlock(page->frame);
			return ok;
		}
	}
	return false;
}

//将从用户虚拟地址升级到内核虚拟地址KPAGE的映射添加到页表
//如果WRITABLE为true，则用户进程可以修改页面；否则，它是只读的
//升级不能已经映射
//KPAGE应该是使用palloc_get_page（）从用户池中获取的页面
//成功时返回true；如果升级已映射或内存分配失败，则返回false
static bool install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t=thread_current();
//验证在该虚拟地址上还没有页面，然后将我们的页面映射到那里
	return (pagedir_get_page(t->pagedir,upage)==NULL&&pagedir_set_page(t->pagedir,upage,kpage,writable));
}
