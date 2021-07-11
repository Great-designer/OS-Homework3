#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>

#include<hash.h>
#include"threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
{
//归thread.c所有
	tid_t tid;//线程标识符
	enum thread_status status;//线程状态
	char name[16];//用于调试的目的
	uint8_t *stack;//已保存堆栈指针
	int priority;//优先
	struct list_elem allelem;//所有线程的列表元素列表
//在thread.c和synch.c之间共享
	struct list_elem elem;//列表元素

//#ifdef USERPROG
//由userprog/process.c所有
	uint32_t *pagedir;//页面目录
	struct hash *pages;//页表
	struct file *bin_file;//二进制可执行文件
//#endif

//属于process.c
	int exit_code;//退出代码
	struct wait_status *wait_status;//此进程的完成状态
	struct list children;//子线程完成情况
//闹钟
	int64_t wakeup_time;//是时候唤醒这条线索
	struct list_elem timer_elem;//计时器等待列表中的元素
	struct semaphore timer_sema;//信号灯
//由syscall.c拥有
	struct list fds;//文件描述符列表
	struct list mappings;//内存映射文件
	int next_handle;//下一个句柄值
	void *user_esp;//用户的堆栈指针

//归thread.c所有
	unsigned magic;//检测堆栈溢出
};

//跟踪进程的完成情况
//父级在其“children”列表中保留的引用，子级在其“wait\u status”指针中保留的引用
struct wait_status
{
	struct list_elem elem;//子列表元素
	struct lock lock;//保护参考
	int ref_cnt;//2=子项和父项都处于活动状态，1=子项或父项都处于活动状态，0=子项和父项都已死亡
	tid_t tid;//子线程id
	int exit_code;//子线程出口代码，如果死亡。
	struct semaphore dead;//1=子线程还活着，0=子线程死了
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
