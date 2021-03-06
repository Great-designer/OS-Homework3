#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "vm/page.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

//页面错误处理程序。这是一个骨架，必须填充它才能实现虚拟内存。
//项目2的一些解决方案可能还需要修改此代码。
//在输入时，出错的地址在CR2（控制寄存器2）中，有关错误的信息（格式如exception.h中的PF_x宏所述）在F的error_code成员中。
//这里的示例代码展示了如何解析这些信息。
//您可以在[IA32-v3a]第5.15节“异常和中断引用”中“中断14——页面错误异常（#PF）”的描述中找到这两个问题的更多信息。
static void page_fault(struct intr_frame *f) 
{
	bool not_present;//True:不存在页，false:正在写入r/o页。
	bool write;//True:访问被写入，false:访问被读取。
	bool user;//按True:用户访问。false:内核访问。
	void *fault_addr;//故障地址。
//获取错误地址，即访问导致错误的虚拟地址。
//它可能指向代码或数据。
//导致错误的不一定是指令的地址（即f->eip）。
//参见[IA32-v2a]“MOV——移动到/移出控制寄存器”和[IA32-v3a]5.15“中断14——页面错误异常（#PF）”。
	asm ("movl %%cr2, %0" : "=r" (fault_addr));
//重新打开中断（它们被关闭，这样我们就可以确保在CR2改变之前读取它）。
	intr_enable();
//统计页面错误。
	page_fault_cnt++;
//确定原因。
	not_present=(f->error_code&PF_P)==0;
	write=(f->error_code&PF_W)!=0;
	user=(f->error_code&PF_U)!=0;
	if(user&&not_present)//允许页面尝试处理它
	{
		if(!page_in(fault_addr))
		{
			thread_exit();
		}
		return;
	}
//要实现虚拟内存，请删除函数体的其余部分，并将其替换为引入fault_addr所指页面的代码。
	printf("Page fault at %p: %s error %s page in %s context.\n",fault_addr,not_present ? "not present" : "rights violation",write ? "writing" : "reading",user ? "user" : "kernel");
	kill(f);
}

