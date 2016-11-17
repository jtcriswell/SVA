/*===- interrupt.c - SVA Execution Engine  --------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements the SVA instructions for registering interrupt and
 * exception handlers.
 *
 *===----------------------------------------------------------------------===
 */

#include "sva/callbacks.h"
#include "sva/config.h"
#include "sva/interrupt.h"
#include "sva/state.h"
#include "sva/keys.h"
#include "sva/util.h"

/* Debug flags for printing data */
#define DEBUG       0

/* Definitions of LLVA specific exceptions */
#define sva_syscall_exception   (31)
#define sva_interrupt_exception (30)
#define sva_exception_exception (29)
#define sva_state_exception     (28)
#define sva_safemem_exception   (27)

extern void * interrupt_table[256];

/* Definitions of functions and variables related to the stack 
   that is used for finding the next free thread.
*/
#define THREAD_SIZE 10000
#define spin_lock(l)  while (__sync_lock_test_and_set((l), 1))
#define spin_unlock(l) __sync_lock_release((l))
#define init_lock(l) *(l) = 0
#define NULL  0

/* Pre-allocate a large number of SVA Threads */
static struct SVAThread realThreads[4096] __attribute__ ((aligned (16)))
__attribute__ ((section ("svamem")));

struct SVAThread *Threads = realThreads;

typedef volatile int lock_t;

/* Stack for storing the free treads */
struct FT_stack{
  struct SVAThread *threads[THREAD_SIZE];
  int top;
  int initialized;
  lock_t lock;
};

/* Initialization of the stack */
static struct FT_stack fthreads __attribute__ ((aligned (16))) __attribute__ ((section ("svamem"))) = {
  .top = -1,
  .lock = 0,
  .initialized = 0,
};

/* Push function for the stack. The action has to be protected by a spinlock. */
void ftstack_push(struct SVAThread *thread){
  spin_lock(&fthreads.lock);

  fthreads.top++;
  fthreads.threads[fthreads.top] = thread;

  spin_unlock(&fthreads.lock);
}

/* Pop function for the stack. */
struct SVAThread *ftstack_pop(void) {

  struct SVAThread *result = NULL;

  spin_lock(&fthreads.lock);

  if(!fthreads.initialized) {

    for (unsigned index = 0; index < 4096; ++index) {
      Threads[index].used = 0;
      fthreads.top++;
      fthreads.threads[fthreads.top] = &Threads[index];
    }

    fthreads.initialized = 1;
  }

  if(fthreads.top == -1) {
    spin_unlock(&fthreads.lock);
    panic("");
    return NULL;
  }
  
  result = fthreads.threads[fthreads.top];
  fthreads.top--;

  spin_unlock(&fthreads.lock);

  return result;
}




/*
 * Default LLVA interrupt, exception, and system call handlers.
 */
void
default_interrupt (unsigned int number, uintptr_t address) {
#if 1
  printf ("SVA: default interrupt handler: %d %d\n", number, address);
#else
  __asm__ __volatile__ ("hlt");
#endif
  return;
}

void
invalidIC (unsigned int v) {
  extern void assertGoodIC (void);

  /*
   * Check that the interrupt context is okay (other than its valid field not
   *  being one
   */
  assertGoodIC();

  /* Print out the interrupt context */
  if (v)
    sva_print_icontext ("invalidIC:trap");
  else
    sva_print_icontext ("invalidIC:sys");

  panic ("SVA: Invalid Interrupt Context\n");
  __asm__ __volatile__ ("hlt\n");
  return;
}

/*
 * Structure: CPUState
 *
 * Description:
 *  This is a structure containing the per-CPU state of each processor in the
 *  system.  We gather this here so that it's easy to find them from the %GS
 *  register.
 */
static struct CPUState realCPUState[numProcessors] __attribute__((aligned(16)))
__attribute__ ((section ("svamem")));
struct CPUState * CPUState = realCPUState;


void
init_threads(void) {
  return;
}

/*
 * Function: randomNumber()
 *
 * Description:
 *  Use the rdrand instruction to generate a 64-bit random number.
 */
static inline uintptr_t
randomNumber (void) {
  uintptr_t rand;
  __asm__ __volatile__ ("1: rdrand %0\n"
                        "jae 1\n" : "=r" (rand));
  return rand;
}

/*
 * Function: findNextFreeThread()
 *
 * Description:
 *  This function returns the index of the next thread which is not in use.
 */
struct SVAThread *
findNextFreeThread (void) {
  /*
   * Find the next free thread.
   */
  struct SVAThread *newThread = ftstack_pop();
  if (newThread) {
    /*
     * Do some basic initialization of the thread.
     */
    newThread->integerState.valid = 0;
    newThread->savedICIndex = 0;
    newThread->ICFPIndex = 0;
    newThread->secmemSize = 0;
    newThread->numPushTargets = 0;
    newThread->secmemPML4e = 0;
    newThread->isInitialForCPU = 0;

    /* 
     * This function currently sets the thread secret with a default
     * statically defined key.  However, in the future will obtain said key
     * from the executable image.  There is also some issue with
     * bootstrapping the initial key and whether or not on the first
     * execution of an application the key will need to be generated by SVA.
     * Thus, future design is yet to be done, however, the following function
     * should suffice to enable any of the above scenarios.
     *
     * TODO: The function currently uses a dummy static key, but in the
     * future will obtain the key from the executable image and then
     * decrypted with the VirtualGhost private key. 
     */
    if (vg) {
      init_thread_key(newThread);
    }

#if DEBUG
    printf("<<<< SVA: Created new private key: value: %s\n",
            newThread->secret.key); 
#endif

    /*
     * Use the next-to-last interrupt context in the list as the first
     * interrupt context.  This may be slightly wasteful, but it's a little
     * easier to make it work correctly right now.
     *
     * The processor's IST3 field should be configured so that the next
     * interrupt context is at maxIC - 2.
     */
    sva_icontext_t * icontextp = newThread->interruptContexts + maxIC - 1;
    newThread->integerState.ist3 = ((uintptr_t) icontextp) - 0x10;
    newThread->integerState.kstackp = newThread->integerState.ist3; 

    /*
     * Generate a random identifier for the new thread.
     */
    if (vg) {
      newThread->rid = randomNumber();
    }
    return newThread;
  }

  panic ("SVA: findNextFreeThread: Exhausted SVA Threads!\n");
  return 0;
}

/*
 * Intrinsic: sva_getCPUState()
 *
 * Description:
 *  Initialize and return a pointer to the per-processor CPU state for this
 *  processor.
 *
 * Input:
 *  tssp - A pointer to the TSS that is currently maintained by the system
 *         software.
 *
 * Notes:
 *  This intrinsic is only here to bootstrap the implementation of SVA.  Once
 *  the SVA interrupt handling code is working properly, this intrinsic should
 *  be removed.
 */
void *
sva_getCPUState (tss_t * tssp) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();


  /* Index of next available CPU state */
  static int nextIndex __attribute__ ((section ("svamem"))) = 0;
  struct SVAThread * st;
  int index;

  if (nextIndex < numProcessors) {
    /*
     * Fetch an unused CPUState from the set of those available.
     */
    index = __sync_fetch_and_add (&nextIndex, 1);
    struct CPUState * cpup = CPUState + index;

    /*
     * The first thread to be allocated is the initial thread that starts
     * SVA for this processor (CPU).  Create an initial thread for this CPU
     * and mark it as an initial thread for this CPU.
     */
    cpup->currentThread = st = findNextFreeThread();
    st->isInitialForCPU = 1;

    /*
     * Flag that the floating point unit has not been used.
     */
    getCPUState()->fp_used = 0;

    /* No one has used the floating point unit yet */
    getCPUState()->prevFPThread = 0;

    /*
     * Initialize a dummy interrupt context so that it looks like we
     * started the processor by taking a trap or system call.  The dummy
     * Interrupt Context should cause a fault if we ever try to put it back
     * on to the processor.
     */
    cpup->newCurrentIC = cpup->currentThread->interruptContexts + (maxIC - 1);
    cpup->newCurrentIC->rip     = 0xfead;
    cpup->newCurrentIC->cs      = 0x43;
    cpup->newCurrentIC->fpstate = 0;
    cpup->gip                   = 0;

    /*
     * Initialize the TSS pointer so that the SVA VM can find it when needed.
     */
    cpup->tssp = tssp;

    /*
     * Setup the Interrupt Stack Table (IST) entry so that the hardware places
     * the stack frame inside SVA memory.
     */
    tssp->ist3 = ((uintptr_t) (st->integerState.ist3));

    /*
     * Return the CPU State to the caller.
     */


    record_tsc(sva_getCPUState_1_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
    return cpup;
  }

  record_tsc(sva_getCPUState_2_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return 0;
}

/*
 * Intrinsic: sva_icontext_setretval()
 *
 * Descrption:
 *  This intrinsic permits the system software to set the return value of
 *  a system call.
 *
 * Notes:
 *  This intrinsic mimics the syscall convention of FreeBSD.
 */
void
sva_icontext_setretval (unsigned long high,
                        unsigned long low,
                        unsigned char error) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /*
   * FIXME: This should ensure that the interrupt context is for a system
   *        call.
   *
   * Get the current processor's user-space interrupt context.
   */
  sva_icontext_t * icontextp = getCPUState()->newCurrentIC;

  /*
   * Set the return value.  The high order bits go in %edx, and the low
   * order bits go in %eax.
   */
  icontextp->rdx = high;
  icontextp->rax = low;

  /*
   * Set or clear the carry flags of the EFLAGS register depending on whether
   * the system call succeeded for failed.
   */
  if (error) {
    icontextp->rflags |= 1;
  } else {
    icontextp->rflags &= 0xfffffffffffffffeu;
  }

  usersva_to_kernel_pcid();
  record_tsc(sva_icontext_setretval_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Intrinsic: sva_icontext_restart()
 *
 * Description:
 *  This intrinsic modifies a user-space interrupt context so that it restarts
 *  the specified system call.
 *
 * TODO:
 *  o Check that the interrupt context is for a system call.
 *  o Remove the extra parameters used for debugging.
 */
void
sva_icontext_restart (unsigned long r10, unsigned long rip) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /*
   * FIXME: This should ensure that the interrupt context is for a system
   *        call.
   *
   * Get the current processor's user-space interrupt context.
   */
  sva_icontext_t * icontextp = getCPUState()->newCurrentIC;

  /*
   * Modify the saved %rcx register so that it re-executes the syscall
   * instruction.  We do this by reducing it by 2 bytes.
   */
  icontextp->rcx -= 2;
  usersva_to_kernel_pcid();
  record_tsc(sva_icontext_restart_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Intrinsic: sva_register_general_exception()
 *
 * Description:
 *  Register a fault handler with the Execution Engine.  The handlers for these
 *  interrupts do not take any arguments.
 *
 * Return value:
 *  0 - No error
 *  1 - Some error occurred.
 */
unsigned char
sva_register_general_exception (unsigned char number,
                                genfault_handler_t handler) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  /*
   * First, ensure that the exception number is within range.
   */
#if 0
  if (number > 31) {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_exception_exception));
    return 1;
  }

  /*
   * Ensure that this is not one of the special handlers.
   */
  switch (number) {
    case 8:
    case 10:
    case 11:
    case 12:
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_exception_exception));
      return 1;
      break;

    default:
      break;
  }
#endif

  /*
   * Put the handler into our dispatch table.
   */
  interrupt_table[number] = handler;

  record_tsc(sva_register_general_exception_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return 0;
}

/*
 * Intrinsic: sva_register_memory_exception()
 *
 * Description:
 *  Register a fault with the Execution Engine.  This fault handler will need
 *  the memory address that was used by the instruction when the fault occurred.
 */
unsigned char
sva_register_memory_exception (unsigned char number, memfault_handler_t handler) {
  /*
   * Ensure that this is not one of the special handlers.
   */
#if 0
  switch (number) {
    case 14:
    case 17:
      /*
       * Put the interrupt handler into our dispatch table.
       */
      interrupt_table[number] = handler;
      return 0;

    default:
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_exception_exception));
      return 1;
  }
#endif

  return 0;
}

/*
 * Intrinsic: sva_register_interrupt ()
 *
 * Description:
 *  This intrinsic registers an interrupt handler with the Execution Engine.
 */
unsigned char
sva_register_interrupt (unsigned char number, interrupt_handler_t interrupt) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();


  /*
   * Ensure that the number is within range.
   */
#if 0
  if (number < 32) {
    __asm__ __volatile__ ("int %0\n" :: "i" (sva_interrupt_exception));
    return 1;
  }
#endif

  /*
   * Put the handler into the system call table.
   */
  interrupt_table[number] = interrupt;

  record_tsc(sva_register_interrupt_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return 0;
}

#if 0
/**************************** Inline Functions *******************************/

/*
 * Intrinsic: sva_load_lif()
 *
 * Description:
 *  Enables or disables local processor interrupts, depending upon the flag.
 *
 * Inputs:
 *  0  - Disable local processor interrupts
 *  ~0 - Enable local processor interrupts
 */
void
sva_load_lif (unsigned int enable)
{
  if (enable)
    __asm__ __volatile__ ("sti":::"memory");
  else
    __asm__ __volatile__ ("cli":::"memory");
}
                                                                                
/*
 * Intrinsic: sva_save_lif()
 *
 * Description:
 *  Return whether interrupts are currently enabled or disabled on the
 *  local processor.
 */
unsigned int
sva_save_lif (void)
{
  unsigned int eflags;

  /*
   * Get the entire eflags register and then mask out the interrupt enable
   * flag.
   */
  __asm__ __volatile__ ("pushf; popl %0\n" : "=r" (eflags));
  return (eflags & 0x00000200);
}

unsigned int
sva_icontext_lif (void * icontextp)
{
  sva_icontext_t * p = icontextp;
  return (p->eflags & 0x00000200);
}

/*
 * Intrinsic: sva_nop()
 *
 * Description:
 *  Provides a volatile operation that does nothing.  This is useful if you
 *  want to wait for an interrupt but don't want to actually do anything.  In
 *  such a case, you need a "filler" instruction that can be interrupted.
 *
 * TODO:
 *  Currently, we're going to use this as an optimization barrier.  Do not move
 *  loads and stores around this.  This is okay, since LLVM will enforce the
 *  same restriction on the LLVM level.
 */
void
sva_nop (void)
{
  __asm__ __volatile__ ("nop" ::: "memory");
}

void
sva_nop1 (void)
{
  __asm__ __volatile__ ("nop" ::: "memory");
}
#endif
