#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include<string.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "vm/page.h"

static int sys_halt(void);
static int sys_exit(int status);
static int sys_exec(const char *ufile);
static int sys_wait(tid_t);
static int sys_create(const char *ufile,unsigned initial_size);
static int sys_remove(const char *ufile);
static int sys_open(const char *ufile);
static int sys_filesize(int handle);
static int sys_read(int handle,void *udst_,unsigned size);
static int sys_write(int handle,void *usrc_,unsigned size);
static int sys_seek(int handle,unsigned position);
static int sys_tell(int handle);
static int sys_close(int handle);
static int sys_mmap(int handle,void *addr);
static int sys_munmap(int mapping);

static void syscall_handler (struct intr_frame *);

static void copy_in(void *,const void *,size_t);

static struct lock fs_lock;

void syscall_init(void) 
{
	intr_register_int(0x30,3,INTR_ON,syscall_handler,"syscall");
	lock_init(&fs_lock);
}

//static void syscall_handler(struct intr_frame *f UNUSED) 
//{
//	printf("system call!\n");
//	thread_exit();
//}

//系统调用处理程序
static void syscall_handler(struct intr_frame *f)
{
	typedef int syscall_function (int, int, int);
//系统调用
	struct syscall
	{
		size_t arg_cnt;//参数数
		syscall_function *func;//实施
    };
//系统调用表
	static const struct syscall syscall_table[] =
	{
		{0, (syscall_function *) sys_halt},
		{1, (syscall_function *) sys_exit},
		{1, (syscall_function *) sys_exec},
		{1, (syscall_function *) sys_wait},
		{2, (syscall_function *) sys_create},
		{1, (syscall_function *) sys_remove},
		{1, (syscall_function *) sys_open},
		{1, (syscall_function *) sys_filesize},
		{3, (syscall_function *) sys_read},
		{3, (syscall_function *) sys_write},
		{2, (syscall_function *) sys_seek},
		{1, (syscall_function *) sys_tell},
		{1, (syscall_function *) sys_close},
		{2, (syscall_function *) sys_mmap},
		{1, (syscall_function *) sys_munmap},
	};
	const struct syscall *sc;
	unsigned call_nr;
	int args[3];
//接到系统呼叫
	copy_in (&call_nr, f->esp, sizeof call_nr);
	if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
	{
		thread_exit ();
	}
	sc = syscall_table + call_nr;
//获取系统调用参数
	ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);
	memset (args, 0, sizeof args);
	copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);
//执行系统调用，并设置返回值
	f->eax = sc->func (args[0], args[1], args[2]);
}

//将大小字节从用户地址USRC复制到内核地址DST
//如果任何用户访问无效，则调用thread_exit（）
static void copy_in(void *dst_,const void *usrc_,size_t size)
{
	uint8_t *dst = dst_;
	const uint8_t *usrc = usrc_;
	while (size > 0)
	{
		size_t chunk_size = PGSIZE - pg_ofs (usrc);
		if (chunk_size > size)
		{
			chunk_size = size;
		}
		if (!page_lock (usrc, false))
		{
			thread_exit ();
		}
		memcpy (dst, usrc, chunk_size);
		page_unlock (usrc);
		dst += chunk_size;
		usrc += chunk_size;
		size -= chunk_size;
	}
}

//在内核内存中创建用户字符串US的副本，并将其作为必须使用palloc_free_page（）释放的页返回
//截断大小为PGSIZE字节的字符串
//如果任何用户访问无效，则调用thread_exit（）
static char *copy_in_string(const char *us)
{
	char *ks;
	char *upage;
	size_t length;
	ks = palloc_get_page (0);
	if (ks == NULL)
	{
		thread_exit ();
	}
	length = 0;
	for(;;)
	{
		upage = pg_round_down (us);
		if (!page_lock (upage, false))
		{
			goto lock_error;
		}
		for (; us < upage + PGSIZE; us++)
		{
			ks[length++] = *us;
			if (*us == '\0')
			{
				page_unlock (upage);
				return ks;
			}
			else if (length >= PGSIZE)
			{
				goto too_long_error;
			}
		}
		page_unlock (upage);
	}
too_long_error:
	page_unlock (upage);
lock_error:
	palloc_free_page (ks);
	thread_exit ();
}

//暂停系统调用
static int sys_halt(void)
{
	shutdown_power_off ();
}

//退出系统调用
static int sys_exit(int exit_code)
{
	thread_current()->exit_code=exit_code;
	thread_exit();
	NOT_REACHED();
}

//执行系统调用
static int sys_exec(const char *ufile)
{
	tid_t tid;
	char *kfile = copy_in_string (ufile);
	lock_acquire (&fs_lock);
	tid = process_execute (kfile);
	lock_release (&fs_lock);
	palloc_free_page (kfile);
	return tid;
}

//等待系统调用
static int sys_wait(tid_t child)
{
	return process_wait(child);
}

//创建系统调用
static int sys_create(const char *ufile,unsigned initial_size)
{
	char *kfile = copy_in_string (ufile);
	bool ok;
	lock_acquire (&fs_lock);
	ok = filesys_create (kfile, initial_size);
	lock_release (&fs_lock);
	palloc_free_page (kfile);
	return ok;
}

//删除系统调用
static int sys_remove(const char *ufile)
{
	char *kfile = copy_in_string (ufile);
	bool ok;
	lock_acquire (&fs_lock);
	ok = filesys_remove (kfile);
	lock_release (&fs_lock);
	palloc_free_page (kfile);
	return ok;
}

//一种文件描述符，用于将文件句柄绑定到文件
struct file_descriptor
{
	struct list_elem elem;//列表元素
	struct file *file;//文件
	int handle;//文件句柄
};

//开放系统调用
static int sys_open(const char *ufile)
{
	char *kfile = copy_in_string (ufile);
	struct file_descriptor *fd;
	int handle = -1;
	fd = malloc (sizeof *fd);
	if (fd != NULL)
	{
		lock_acquire (&fs_lock);
		fd->file = filesys_open (kfile);
		if (fd->file != NULL)
		{
			struct thread *cur = thread_current ();
			handle = fd->handle = cur->next_handle++;
			list_push_front (&cur->fds, &fd->elem);
		}
		else
		{
			free (fd);
		}
		lock_release (&fs_lock);
	}
	palloc_free_page (kfile);
	return handle;
}

//返回与给定句柄关联的文件描述符
//如果句柄与打开的文件不关联，则终止进程
static struct file_descriptor *lookup_fd(int handle)
{
	struct thread *cur=thread_current();
	struct list_elem *e;
	for(e=list_begin(&cur->fds);e!=list_end(&cur->fds);e=list_next(e))
	{
		struct file_descriptor *fd;
		fd=list_entry(e,struct file_descriptor,elem);
		if(fd->handle==handle)
		{
			return fd;
		}
	}
	thread_exit();
}

//文件大小系统调用
static int sys_filesize(int handle)
{
	struct file_descriptor *fd=lookup_fd(handle);
	int size;
	lock_acquire(&fs_lock);
	size=file_length(fd->file);
	lock_release(&fs_lock);
	return size;
}

//读取系统调用
static int sys_read(int handle, void *udst_, unsigned size)
{
	uint8_t *udst = udst_;
	struct file_descriptor *fd;
	int bytes_read = 0;
	fd = lookup_fd (handle);
	while (size > 0)
	{
//这一页要读多少
		size_t page_left = PGSIZE - pg_ofs (udst);
		size_t read_amt = size < page_left ? size : page_left;
		off_t retval;
//从文件读入页面
		if (handle != STDIN_FILENO)
		{
			if (!page_lock (udst, true))
			{
				thread_exit ();
			}
			lock_acquire (&fs_lock);
			retval = file_read (fd->file, udst, read_amt);
			lock_release (&fs_lock);
			page_unlock (udst);
		}
		else
		{
			size_t i;
			for (i = 0; i < read_amt; i++)
			{
				char c = input_getc ();
				if (!page_lock (udst, true))
				{
					thread_exit ();
				}
				udst[i] = c;
				page_unlock (udst);
			}
			bytes_read = read_amt;
		}
//检查成功
		if (retval < 0)
		{
			if (bytes_read == 0)
			{
				bytes_read = -1;
			}
			break;
		}
		bytes_read += retval;
		if (retval != (off_t) read_amt)
		{
//简读一下，我们说完了
			break;
		}
//前进
		udst += retval;
		size -= retval;
	}
	return bytes_read;
}

//写入系统调用
static int sys_write(int handle, void *usrc_, unsigned size)
{
	uint8_t *usrc = usrc_;
	struct file_descriptor *fd = NULL;
	int bytes_written = 0;
//查找文件描述符
	if (handle != STDOUT_FILENO)
	{
		fd = lookup_fd (handle);
	}
	while (size > 0)
	{
//要写入此页多少字节
		size_t page_left = PGSIZE - pg_ofs (usrc);
		size_t write_amt = size < page_left ? size : page_left;
		off_t retval;
//从页面写入文件
		if (!page_lock (usrc, false))
		{
			thread_exit ();
		}
		lock_acquire (&fs_lock);
		if (handle == STDOUT_FILENO)
		{
			putbuf ((char *) usrc, write_amt);
			retval = write_amt;
		}
		else
		{
			retval = file_write (fd->file, usrc, write_amt);
		}
		lock_release (&fs_lock);
		page_unlock (usrc);
//处理返回值
		if (retval < 0)
		{
			if (bytes_written == 0)
			{
				bytes_written = -1;
			}
			break;
		}
		bytes_written += retval;
//如果是一篇短文，我们就完事了
		if (retval != (off_t) write_amt)
		{
			break;
		}
//前进
		usrc += retval;
		size -= retval;
	}
	return bytes_written;
}

//查找系统调用
static int sys_seek(int handle,unsigned position)
{
	struct file_descriptor *fd=lookup_fd(handle);
	lock_acquire(&fs_lock);
	if((off_t)position>=0)
	{
		file_seek(fd->file,position);
	}
	lock_release(&fs_lock);
	return 0;
}


//告诉系统呼叫
static int sys_tell(int handle)
{
	struct file_descriptor *fd = lookup_fd (handle);
	unsigned position;
	lock_acquire (&fs_lock);
	position = file_tell (fd->file);
	lock_release (&fs_lock);
	return position;
}

//关闭系统调用
static int sys_close(int handle)
{
	struct file_descriptor *fd = lookup_fd (handle);
	lock_acquire (&fs_lock);
	file_close (fd->file);
	lock_release (&fs_lock);
	list_remove (&fd->elem);
	free (fd);
	return 0;
}

//将映射id绑定到内存区域和文件
struct mapping
{
	struct list_elem elem;//列表元素
	int handle;//映射id
	struct file *file;//文件
	uint8_t *base;//开始内存映射
	size_t page_cnt;//映射的页数
};

//返回与给定句柄关联的文件描述符
//如果句柄与内存映射不关联，则终止进程
static struct mapping *lookup_mapping(int handle)
{
	struct thread *cur=thread_current();
	struct list_elem *e;
	for(e=list_begin(&cur->mappings);e!=list_end(&cur->mappings);e=list_next(e))
	{
		struct mapping *m=list_entry(e,struct mapping,elem);
		if(m->handle==handle)
		{
			return m;
		}
	}
	thread_exit();
}

//从虚拟地址空间中删除映射M，写回所有已更改的页
static void unmap(struct mapping *m)
{
//从该进程的映射列表中删除此映射
	list_remove(&m->elem);
//对于内存映射文件中的每个页
	for(int i = 0; i < m->page_cnt; i++)
	{
//确定页面是否脏（已修改）。如果是这样，请将该页写回磁盘
		if (pagedir_is_dirty(thread_current()->pagedir, ((const void *) ((m->base) + (PGSIZE * i)))))
		{
			lock_acquire (&fs_lock);
			file_write_at(m->file, (const void *) (m->base + (PGSIZE * i)), (PGSIZE*(m->page_cnt)), (PGSIZE * i));
			lock_release (&fs_lock);
		}
	}
//最后，释放所有内存映射页（释放进程内存）
	for(int i = 0; i < m->page_cnt; i++)
	{
		page_deallocate((void *) ((m->base) + (PGSIZE * i)));
	}
}

//Mmap系统调用
static int sys_mmap(int handle,void *addr)
{
	struct file_descriptor *fd = lookup_fd (handle);
	struct mapping *m = malloc (sizeof *m);
	size_t offset;
	off_t length;
	if (m == NULL || addr == NULL || pg_ofs (addr) != 0)
	{
		return -1;
	}
	m->handle = thread_current ()->next_handle++;
	lock_acquire (&fs_lock);
	m->file = file_reopen (fd->file);
	lock_release (&fs_lock);
	if (m->file == NULL)
	{
		free (m);
		return -1;
	}
	m->base = addr;
	m->page_cnt = 0;
	list_push_front (&thread_current ()->mappings, &m->elem);
	offset = 0;
	lock_acquire (&fs_lock);
	length = file_length (m->file);
	lock_release (&fs_lock);
	while (length > 0)
	{
		struct page *p = page_allocate ((uint8_t *) addr + offset, false);
		if (p == NULL)
		{
			unmap (m);
			return -1;
		}
		p->private = false;
		p->file = m->file;
		p->file_offset = offset;
		p->file_bytes = length >= PGSIZE ? PGSIZE : length;
		offset += p->file_bytes;
		length -= p->file_bytes;
		m->page_cnt++;
	}
	return m->handle;
}

//Munmap系统调用
static int sys_munmap(int mapping)
{
//获取与给定映射id对应的映射，并尝试取消映射
	struct mapping *map=lookup_mapping(mapping);
	unmap(map);
	return 0;
}

//在线程退出时，关闭所有打开的文件并取消映射所有映射
void syscall_exit(void)
{
	struct thread *cur = thread_current ();
	struct list_elem *e, *next;
	for (e = list_begin (&cur->fds); e != list_end (&cur->fds); e = next)
	{
		struct file_descriptor *fd = list_entry (e, struct file_descriptor, elem);
		next = list_next (e);
		lock_acquire (&fs_lock);
		file_close (fd->file);
		lock_release (&fs_lock);
		free (fd);
	}
	for (e = list_begin (&cur->mappings); e != list_end (&cur->mappings);e = next)
	{
		struct mapping *m = list_entry (e, struct mapping, elem);
		next = list_next (e);
		unmap (m);
	}
}

