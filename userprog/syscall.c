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

//ϵͳ���ô������
static void syscall_handler(struct intr_frame *f)
{
	typedef int syscall_function (int, int, int);
//ϵͳ����
	struct syscall
	{
		size_t arg_cnt;//������
		syscall_function *func;//ʵʩ
    };
//ϵͳ���ñ�
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
//�ӵ�ϵͳ����
	copy_in (&call_nr, f->esp, sizeof call_nr);
	if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
	{
		thread_exit ();
	}
	sc = syscall_table + call_nr;
//��ȡϵͳ���ò���
	ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);
	memset (args, 0, sizeof args);
	copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);
//ִ��ϵͳ���ã������÷���ֵ
	f->eax = sc->func (args[0], args[1], args[2]);
}

//����С�ֽڴ��û���ַUSRC���Ƶ��ں˵�ַDST
//����κ��û�������Ч�������thread_exit����
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

//���ں��ڴ��д����û��ַ���US�ĸ�������������Ϊ����ʹ��palloc_free_page�����ͷŵ�ҳ����
//�ضϴ�СΪPGSIZE�ֽڵ��ַ���
//����κ��û�������Ч�������thread_exit����
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

//��ͣϵͳ����
static int sys_halt(void)
{
	shutdown_power_off ();
}

//�˳�ϵͳ����
static int sys_exit(int exit_code)
{
	thread_current()->exit_code=exit_code;
	thread_exit();
	NOT_REACHED();
}

//ִ��ϵͳ����
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

//�ȴ�ϵͳ����
static int sys_wait(tid_t child)
{
	return process_wait(child);
}

//����ϵͳ����
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

//ɾ��ϵͳ����
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

//һ���ļ������������ڽ��ļ�����󶨵��ļ�
struct file_descriptor
{
	struct list_elem elem;//�б�Ԫ��
	struct file *file;//�ļ�
	int handle;//�ļ����
};

//����ϵͳ����
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

//�������������������ļ�������
//��������򿪵��ļ�������������ֹ����
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

//�ļ���Сϵͳ����
static int sys_filesize(int handle)
{
	struct file_descriptor *fd=lookup_fd(handle);
	int size;
	lock_acquire(&fs_lock);
	size=file_length(fd->file);
	lock_release(&fs_lock);
	return size;
}

//��ȡϵͳ����
static int sys_read(int handle, void *udst_, unsigned size)
{
	uint8_t *udst = udst_;
	struct file_descriptor *fd;
	int bytes_read = 0;
	fd = lookup_fd (handle);
	while (size > 0)
	{
//��һҳҪ������
		size_t page_left = PGSIZE - pg_ofs (udst);
		size_t read_amt = size < page_left ? size : page_left;
		off_t retval;
//���ļ�����ҳ��
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
//���ɹ�
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
//���һ�£�����˵����
			break;
		}
//ǰ��
		udst += retval;
		size -= retval;
	}
	return bytes_read;
}

//д��ϵͳ����
static int sys_write(int handle, void *usrc_, unsigned size)
{
	uint8_t *usrc = usrc_;
	struct file_descriptor *fd = NULL;
	int bytes_written = 0;
//�����ļ�������
	if (handle != STDOUT_FILENO)
	{
		fd = lookup_fd (handle);
	}
	while (size > 0)
	{
//Ҫд���ҳ�����ֽ�
		size_t page_left = PGSIZE - pg_ofs (usrc);
		size_t write_amt = size < page_left ? size : page_left;
		off_t retval;
//��ҳ��д���ļ�
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
//������ֵ
		if (retval < 0)
		{
			if (bytes_written == 0)
			{
				bytes_written = -1;
			}
			break;
		}
		bytes_written += retval;
//�����һƪ���ģ����Ǿ�������
		if (retval != (off_t) write_amt)
		{
			break;
		}
//ǰ��
		usrc += retval;
		size -= retval;
	}
	return bytes_written;
}

//����ϵͳ����
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


//����ϵͳ����
static int sys_tell(int handle)
{
	struct file_descriptor *fd = lookup_fd (handle);
	unsigned position;
	lock_acquire (&fs_lock);
	position = file_tell (fd->file);
	lock_release (&fs_lock);
	return position;
}

//�ر�ϵͳ����
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

//��ӳ��id�󶨵��ڴ�������ļ�
struct mapping
{
	struct list_elem elem;//�б�Ԫ��
	int handle;//ӳ��id
	struct file *file;//�ļ�
	uint8_t *base;//��ʼ�ڴ�ӳ��
	size_t page_cnt;//ӳ���ҳ��
};

//�������������������ļ�������
//���������ڴ�ӳ�䲻����������ֹ����
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

//�������ַ�ռ���ɾ��ӳ��M��д�������Ѹ��ĵ�ҳ
static void unmap(struct mapping *m)
{
//�Ӹý��̵�ӳ���б���ɾ����ӳ��
	list_remove(&m->elem);
//�����ڴ�ӳ���ļ��е�ÿ��ҳ
	for(int i = 0; i < m->page_cnt; i++)
	{
//ȷ��ҳ���Ƿ��ࣨ���޸ģ���������������뽫��ҳд�ش���
		if (pagedir_is_dirty(thread_current()->pagedir, ((const void *) ((m->base) + (PGSIZE * i)))))
		{
			lock_acquire (&fs_lock);
			file_write_at(m->file, (const void *) (m->base + (PGSIZE * i)), (PGSIZE*(m->page_cnt)), (PGSIZE * i));
			lock_release (&fs_lock);
		}
	}
//����ͷ������ڴ�ӳ��ҳ���ͷŽ����ڴ棩
	for(int i = 0; i < m->page_cnt; i++)
	{
		page_deallocate((void *) ((m->base) + (PGSIZE * i)));
	}
}

//Mmapϵͳ����
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

//Munmapϵͳ����
static int sys_munmap(int mapping)
{
//��ȡ�����ӳ��id��Ӧ��ӳ�䣬������ȡ��ӳ��
	struct mapping *map=lookup_mapping(mapping);
	unmap(map);
	return 0;
}

//���߳��˳�ʱ���ر����д򿪵��ļ���ȡ��ӳ������ӳ��
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

