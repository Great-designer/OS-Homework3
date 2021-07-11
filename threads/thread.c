#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"

#include "userprog/syscall.h"

#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
//static void init_thread(struct thread *, const char *name, int priority);
static void init_thread(struct thread *,const char *name,int priority,tid_t);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

//通过将当前正在运行的代码转换为线程来初始化线程系统
//这在一般情况下是行不通的，在这种情况下是可能的，因为loader.S小心地将堆栈的底部放在页面边界处
//同时初始化运行队列和tid锁
//调用此函数后，请确保在尝试使用thread_create（）创建任何线程之前初始化页分配器
//在该函数完成之前调用thread_current（）是不安全的
void thread_init(void) 
{
	ASSERT(intr_get_level()==INTR_OFF);
	lock_init(&tid_lock);
	list_init(&ready_list);
	list_init(&all_list);
//为正在运行的线程设置线程结构
	initial_thread=running_thread();
//	init_thread(initial_thread,"main",PRI_DEFAULT);
	init_thread(initial_thread,"main",PRI_DEFAULT,0);
	initial_thread->status=THREAD_RUNNING;
//	initial_thread->tid=allocate_tid();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

//使用给定的初始优先级创建名为NAME的新内核线程，该线程执行传递AUX作为参数的函数，并将其添加到就绪队列中
//返回新线程的线程标识符，如果创建失败，则返回TID\u错误
//如果已调用thread_start（），则可以在thread_create（）返回之前调度新线程
//它甚至可以在thread_create（）返回之前退出
//相反，在调度新线程之前，原始线程可以运行任意时间
//如果需要确保排序，请使用信号量或其他形式的同步
//提供的代码将新线程的“priority”成员设置为priority，但没有实现实际的优先级调度
//排程问题的目标是1-3
//tid_t thread_create(const char *name, int priority,thread_func *function, void *aux) 
//{
//	struct thread *t;
//	struct kernel_thread_frame *kf;
//	struct switch_entry_frame *ef;
//	struct switch_threads_frame *sf;
//	tid_t tid;
//	ASSERT (function != NULL);
////分配线程
//	t = palloc_get_page (PAL_ZERO);
//	if (t == NULL)
//	{
//		return TID_ERROR;
//	}
////初始化线程
//	init_thread (t, name, priority);
//	tid = t->tid = allocate_tid ();
////kernel_thread（）的堆栈帧
//	kf = alloc_frame (t, sizeof *kf);
//	kf->eip = NULL;
//	kf->function = function;
//	kf->aux = aux;
////switch_entry（）的堆栈帧
//	ef = alloc_frame (t, sizeof *ef);
//	ef->eip = (void (*) (void)) kernel_thread;
////switch_threads（）的堆栈帧
//	sf = alloc_frame (t, sizeof *sf);
//	sf->eip = switch_entry;
//	sf->ebp = 0;
////添加到运行队列
//	thread_unblock (t);
//	return tid;
//}

//使用给定的初始优先级创建名为NAME的新内核线程，该线程执行传递AUX作为参数的函数，并将其添加到就绪队列中
//返回新线程的线程标识符，如果创建失败，则返回TID\u错误
//如果已调用thread_start（），则可以在thread_create（）返回之前调度新线程
//它甚至可以在thread_create（）返回之前退出
//相反，在调度新线程之前，原始线程可以运行任意时间
//如果需要确保排序，请使用信号量或其他形式的同步
//提供的代码将新线程的“priority”成员设置为priority，但没有实现实际的优先级调度
//排程问题的目标是1-3
tid_t thread_create (const char *name, int priority,thread_func *function, void *aux) 
{
	struct thread *t;
	struct kernel_thread_frame *kf;
	struct switch_entry_frame *ef;
	struct switch_threads_frame *sf;
	tid_t tid;
	enum intr_level old_level;
	ASSERT (function != NULL);
//分配线程
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
	{
		return TID_ERROR;
	}
//初始化线程
	init_thread (t, name, priority, allocate_tid ());
	tid = t->tid;
//通过初始化线程堆栈为首次运行做好准备
//以原子方式执行此操作，以便无法观察“stack”成员的中间值
	old_level = intr_disable ();
//kernel_thread（）的堆栈帧
	kf = alloc_frame (t, sizeof *kf);
	kf->eip = NULL;
	kf->function = function;
	kf->aux = aux;
//switch_entry（）的堆栈帧
	ef = alloc_frame (t, sizeof *ef);
	ef->eip = (void (*) (void)) kernel_thread;
//switch_threads（）的堆栈帧
	sf = alloc_frame (t, sizeof *sf);
	sf->eip = switch_entry;
	sf->ebp = 0;
	intr_set_level (old_level);
//添加到运行队列
	thread_unblock (t);
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_push_back (&ready_list, &t->elem);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

//取消当前线程的计划并销毁它
//永远不要返回调用
void thread_exit (void) 
{
	ASSERT(!intr_context());
	syscall_exit();
#ifdef USERPROG
	process_exit();
#endif
//从“所有线程”列表中删除线程，将状态设置为“正在消亡”，然后安排另一个进程
//当这个进程调用thread_schedule_tail（）时，它将摧毁我们
	intr_disable();
	list_remove(&thread_current()->allelem);
	thread_current()->status=THREAD_DYING;
	schedule();
	NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
    list_push_back (&ready_list, &cur->elem);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  thread_current ()->priority = new_priority;
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  /* Not yet implemented. */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

//将T作为名为NAME的阻塞线程进行基本初始化
//static void init_thread(struct thread *t,const char *name,int priority)
//{
//	enum intr_level old_level;
//	ASSERT (t != NULL);
//	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
//	ASSERT (name != NULL);
//	memset (t, 0, sizeof *t);
//	t->status = THREAD_BLOCKED;
//	strlcpy (t->name, name, sizeof t->name);
//	t->stack = (uint8_t *) t + PGSIZE;
//	t->priority = priority;
//	t->magic = THREAD_MAGIC;
//	old_level = intr_disable ();
//	list_push_back (&all_list, &t->allelem);
//	intr_set_level (old_level);
//}

//将T作为名为NAME的阻塞线程进行基本初始化
static void init_thread(struct thread *t, const char *name, int priority, tid_t tid)
{
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);
	memset (t, 0, sizeof *t);
	t->tid = tid;
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->stack = (uint8_t *) t + PGSIZE;
	t->priority = priority;
	t->exit_code = -1;
	t->wait_status = NULL;
	list_init (&t->children);
	sema_init (&t->timer_sema, 0);
	t->pagedir = NULL;
	t->pages = NULL;
	t->bin_file = NULL;
	list_init (&t->fds);
	list_init (&t->mappings);
	t->next_handle = 2;
	t->magic = THREAD_MAGIC;
	list_push_back (&all_list, &t->allelem);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
