/*===- state.c - SVA Execution Engine  ------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * Provide intrinsics for manipulating the LLVA machine state.
 *
 *===----------------------------------------------------------------------===
 */

#include <string.h>

#if 1
#include <sva/config.h>
#endif
#include <sva/cfi.h>
#include <sva/callbacks.h>
#include <sva/util.h>
#include <sva/state.h>
#include <sva/interrupt.h>
#include <sva/mmu.h>
#include "sva/mmu_intrinsics.h"
#include <sva/x86.h>
#include "thread_stack.h"

/*****************************************************************************
 * Externally Visibile Utility Functions
 ****************************************************************************/

void
installNewPushTarget (void) {
  /* Get the current SVA thread */
  struct SVAThread * threadp = getCPUState()->currentThread;

  /* Get the current interrput context */
  sva_icontext_t * icp = getCPUState()->newCurrentIC;

  /*
   * Make sure we have room for another target.
   */
  if (threadp->numPushTargets == maxPushTargets)
    return;

  /*
   * Add the new target.
   */
  threadp->validPushTargets[(threadp->numPushTargets)++] = (void *) icp->rdi;
  return;
}

/*****************************************************************************
 * Intrinsics for User-Space Applications
 ****************************************************************************/

void
getThreadRID (void) {
  /* Get the current interrput context */
  sva_icontext_t * icp = getCPUState()->newCurrentIC;

  /* Set the rax register with the pointer to the secret key */
  icp->rax = getCPUState()->currentThread->rid;
  return;
}

/*****************************************************************************
 * Interrupt Context Intrinsics
 ****************************************************************************/

/*
 * Intrinsic: sva_icontext_getpc()
 *
 * Description:
 *  Get the native code program counter value out of the interrupt context.
 */
uintptr_t
sva_icontext_getpc (void) {
  uint64_t tsc_tmp;  
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  struct CPUState * cpuState = getCPUState();

  record_tsc(sva_icontext_getpc_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return cpuState->newCurrentIC->rip;
}

/*****************************************************************************
 * Miscellaneous State Manipulation Functions
 ****************************************************************************/

/*
 * Intrinsic: sva_ipush_function5 ()
 *
 * Description:
 *  This intrinsic modifies the most recent interrupt context so that the
 *  specified function is called with the given arguments when the state is
 *  reloaded on to the processor.
 *
 * Inputs:
 *  newf         - The function to call.
 *  p[1|2|3|4|5] - The parameters to pass to the function.
 *
 * TODO:
 *  o This intrinsic should check whether newf is a valid function for the
 *    appropriate mode (user or kernel).
 *
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 */
void
sva_ipush_function5 (void *newf,
                     uintptr_t p1,
                     uintptr_t p2,
                     uintptr_t p3,
                     uintptr_t p4,
                     uintptr_t p5) {
  uint64_t tsc_tmp;  
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();   

  kernel_to_usersva_pcid();

  /* Old interrupt flags */
  uintptr_t rflags;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Get the most recent interrupt context.
   */
  struct SVAThread * threadp = getCPUState()->currentThread;
  sva_icontext_t * ep = getCPUState()->newCurrentIC;

  /*
   * Verify that the target function is in the list of valid function targets.
   * Note that if no push targets have been specified, then any target is valid.
   */
  if (threadp->numPushTargets) {
    unsigned index = 0;
    unsigned char found = 0;
    for (index = 0; index < threadp->numPushTargets; ++index) {
      if (threadp->validPushTargets[index] == newf) {
        found = 1;
        break;
      }
    }

    if (!found) {
      panic ("SVA: Pushing bad value %lx\n", newf);
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      record_tsc(sva_ipush_function5_1_api, ((uint64_t) sva_read_tsc() - tsc_tmp)); 
      return;
    }

    found = 0;
    for (index = 0; index < threadp->numPushTargets; ++index) {
      if (threadp->validPushTargets[index] == ((void *)p5)) {
        found = 1;
        break;
      }
    }

    if (!found) {
      panic ("SVA: Pushing bad sighandler value %lx\n", p5);
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      record_tsc(sva_ipush_function5_2_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
      return;
    }

  }

  /*
   * Check the memory.
   */
  sva_check_memory_write (ep, sizeof (sva_icontext_t));
  sva_check_memory_write (ep->rsp, sizeof (uintptr_t));

  /*
   * Place the arguments into the proper registers.
   */
  ep->rdi = p1;
  ep->rsi = p2;
  ep->rdx = p3;
  ep->rcx = p4;
  ep->r8  = p5;

  /*
   * Push a return program counter value on to the stack.  It should cause a
   * fault if the function returns.
   */
  *(--(ep->rsp)) = 0x0fec;

  /*
   * Set the return function to be the specificed function.
   */
  ep->rip = (uintptr_t) newf;

  /*
   * Mark the interrupt context as valid; if an sva_ialloca previously
   * invalidated it, an sva_ipush_function() makes it valid again.
   */
  ep->valid |= (IC_is_valid);

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();

  record_tsc(sva_ipush_function5_3_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Intrinsic: sva_ipush_function0 ()
 *
 * Description:
 *  This intrinsic modifies the user space process code so that the
 *  specified function was called with the given arguments.
 *
 * Inputs:
 *  newf     - The function to call.
 *
 * NOTES:
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 */
void
sva_ipush_function0 (void (*newf)(void)) {
  sva_ipush_function5 (newf, 0, 0, 0, 0, 0);
  return;
}

/*
 * Intrinsic: sva_ipush_function1 ()
 *
 * Description:
 *  This intrinsic modifies the user space process code so that the
 *  specified function was called with the given arguments.
 *
 * Inputs:
 *  newf     - The function to call.
 *  param    - The parameter to send to the function.
 *
 * TODO:
 *  This currently only takes a function that takes a single integer
 *  argument.  Eventually, this should take any function.
 *
 * NOTES:
 *  o This intrinsic could conceivably cause a memory fault (either by
 *    accessing a stack page that isn't paged in, or by overwriting the stack).
 *    This should be addressed at some point.
 */
void
sva_ipush_function1 (void (*newf)(int), uintptr_t param) {
  sva_ipush_function5 (newf, param, 0, 0, 0, 0);
  return;
}

/*****************************************************************************
 * Integer State
 ****************************************************************************/

/*
 * Function: checkIntegerForLoad ()
 *
 * Description:
 *  Perform all necessary checks on an integer state to make sure that it can
 *  be loaded on to the processor.
 *
 * Inputs:
 *  p - A pointer to the integer state to load.
 *
 * TODO:
 *  The checking code must also verify that there is enough stack space before
 *  proceeding.  Otherwise, state could get really messy.
 */
static inline void
checkIntegerForLoad (sva_integer_state_t * p) {
  /* Current code segment */
  unsigned int cs;

  /* Data segment to use for this privilege level */
  unsigned int ds = 0x18;

  /* Flags whether the input has been validated */
  unsigned int validated = 0;

  /* System call disable mask */
  extern unsigned int sva_sys_disabled;

#if 0
  /* Disable interrupts */
  __asm__ __volatile__ ("cli");
#endif

#if 0
  do
  {
#ifdef SC_INTRINCHECKS
    extern MetaPoolTy IntegerStatePool;
    struct node {
      void* left;
      void* right;
      char* key;
      char* end;
      void* tag;
    };
    struct node * np;
    unsigned long start;

    /*
     * Verify that the memory was part of a previous integer state.
     */
    np = getBounds (&IntegerStatePool, buffer);
    start = np->key;
    pchk_drop_obj (&IntegerStatePool, buffer);
    if (start != buffer)
      poolcheckfail ("Integer Check Failure", (unsigned)buffer, (void*)__builtin_return_address(0));
#endif

    /*
     * Verify that we won't fault if we read from the buffer.
     */
    sva_check_memory_read (buffer, sizeof (sva_integer_state_t));

    /*
     * Verify that we can access the stack pointed to inside the buffer.
     */
    sva_check_memory_write ((p->rsp) - 2, 8);

    /*
     * Grab the current code segment.
     */
    __asm__ __volatile__ ("movl %%cs, %0\n" : "=r" (cs));
    cs &= 0xffff;

    /*
     * If we're not operating at the same privilege level as when this state
     * buffer was saved, then generate an exception.
     */
    if (cs != (p->cs)) {
      __asm__ __volatile__ ("int %0\n" :: "i" (sva_state_exception));
      continue;
    }

#if 0
    /*
     * Configure the data segment to match the code segment, in case it somehow
     * became corrupted.
     */
    ds = ((cs == 0x10) ? (0x18) : (0x2B));
#endif

    /*
     * Validation is finished.  Continue.
     */
    validated = 1;
  } while (!validated);
#endif
  return;
}

/*
 * Function: flushSecureMemory()
 *
 * Description:
 *  This function flushes TLB entries and caches for a thread's secure memory.
 */
static inline void
flushSecureMemory (struct SVAThread * threadp) {
  /*
   * Invalidate all TLBs (including those with the global flag).  We do this
   * by first turning on and then turning off the PCID extension.  According
   * to the Intel Software Architecture Reference Manual, Volume 3,
   * Section 4.10.4, this will do the invalidation that we want.
   *
   * Experiments show that invalidating all of the TLBs is faster than
   * invalidating every page individually.  Since we usually flush on a context
   * switch, we just flushed all the TLBs anyway by changing CR3.  Therefore,
   * we lose speed by not flushing everything again.
   */
  __asm__ __volatile__ ("movq %cr4, %rax\n"
                        "movq %cr4, %rcx\n"
                        "orq $0x20000, %rax\n"
                        "andq $0xfffffffffffdffff, %rcx\n"
                        "movq %rax, %cr4\n"
                        "movq %rcx, %cr4\n");
  return;
}

/*
 * Intrinsic: sva_swap_integer()
 *
 * Description:
 *  This intrinsic saves the current integer state and swaps in a new one.
 *
 * Inputs:
 *  newint - The new integer state to load on to the processor.
 *  statep - A pointer to a memory location in which to store the ID of the
 *           state that this invocation of sva_swap_integer() will save.
 *
 * Return value:
 *  0 - State swapping failed.
 *  1 - State swapping succeeded.
 */
uintptr_t
sva_swap_integer (uintptr_t newint, uintptr_t * statep) {
  uint64_t tsc_tmp;  
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();

  /* Function for saving state */
  extern unsigned int save_integer (sva_integer_state_t * buffer);
  extern void load_integer (sva_integer_state_t * p);

  /* Old interrupt flags */
  uintptr_t rflags = sva_enter_critical();

  /* Pointer to the current CPU State */
  struct CPUState * cpup = getCPUState();

  /*
   * Get a pointer to the memory buffer into which the integer state should be
   * stored.  There is one such buffer for every SVA thread.
   */
  struct SVAThread * oldThread = cpup->currentThread;
  sva_integer_state_t * old = &(oldThread->integerState);

  /* Get a pointer to the saved state (the ID is the pointer) */
  struct SVAThread * newThread = validateThreadPointer(newint);
  if (! newThread) {
	 panic("sva_swap_integer: Invalid new-thread pointer");
	 return (uintptr_t)NULL;
  }
  sva_integer_state_t * new =  newThread ? &(newThread->integerState) : 0;

  /* Variables for registers for debugging */
  uintptr_t rsp, rbp;

  /*
   * If there is no place for new state, flag an error.
   */
  if (!newThread) panic ("SVA: No New Thread!\n");

  /*
   * Determine whether the integer state is valid.
   */
#if SVA_CHECK_INTEGER
  if ((pchk_check_int (new)) == 0) {
    poolcheckfail ("sva_swap_integer: Bad integer state", (unsigned)old, (void*)__builtin_return_address(0));
    /*
     * Re-enable interrupts.
     */
    sva_exit_critical (rflags);
    usersva_to_kernel_pcid();
    record_tsc(sva_swap_integer_1_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
    return 0;
  }
#endif

  /*
   * Save the value of the current kernel stack pointer, IST3, currentIC, and
   * the pointer to the global invoke frame pointer.
   */
  old->kstackp   = cpup->tssp->rsp0;
  old->ist3      = cpup->tssp->ist3;
  old->currentIC = cpup->newCurrentIC;
  old->ifp       = cpup->gip;

  /*
   * Save the current integer state.  Note that returning from sva_integer()
   * with a non-zero value means that we've just woken up from a context
   * switch.
   */
  if (save_integer (old)) {
    /*
     * We've awakened.
     */
#if SVA_CHECK_INTEGER
    /*
     * Mark the integer state invalid and return to the caller.
     */
    pchk_drop_int (old);

    /*
     * Determine what stack we're running on now.
     */
    pchk_update_stack ();
#endif

    /*
     * Re-enable interrupts.
     */
    sva_exit_critical (rflags);
    usersva_to_kernel_pcid();
    record_tsc(sva_swap_integer_2_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
    return 1;
  }

  /*
   * Save this functions return address because it can be overwritten by
   * calling interim FreeBSD code that does a native FreeBSD context switch.
   */
  old->hackRIP = (uintptr_t) __builtin_return_address(0);

  /*
   * If the current state is using secure memory, we need to flush out the TLBs
   * and caches that might contain it.
   */
  if (vg && (oldThread->secmemSize)) {
    /*
     * Save the CR3 register.  We'll need it later for sva_release_stack().
     */
    uintptr_t cr3;
    __asm__ __volatile__ ("movq %%cr3, %0\n" : "=r" (cr3));
    old->cr3 = cr3;

    /*
     * Get a pointer into the page tables for the secure memory region.
     */
    pml4e_t * secmemp = (pml4e_t *) getVirtual((uintptr_t)(get_pagetable() + secmemOffset));

    /*
     * Mark the secure memory is unmapped in the page tables.
     */
    unprotect_paging ();
    *secmemp &= ~(PTE_PRESENT);
    protect_paging ();

    /*
     * Flush the secure memory page mappings.
     */
    flushSecureMemory (oldThread);
  }

  /*
   * Turn off access to the Floating Point Unit (FPU).  We will leave this
   * state on the CPU but force a trap if another process attempts to use it.
   *
   * We place this code here since, when Virtual Ghost is enabled, the call to
   * unprotect_paging() and protect_paging() will flush the pipeline with a
   * write to CR0.  This code may also cause a pipeline flush, so we place it
   * close to the other pipeline flushing code to reduce the amount of code
   * executed between flushes. 
   */
  const unsigned long mp = 0x00000002u;
  const unsigned long em = 0x00000004u;
  const unsigned long ts = 0x00000008u;
  unsigned long cr0;
  __asm__ __volatile__ ("mov %%cr0, %0\n"
                        "and  %1, %0\n"
                        "or   %2, %0\n"
                        "mov %0, %%cr0\n"
                        : "=&r" (cr0)
                        : "r" (~(em)),
                          "r" (mp | ts));

  /*
   * Mark the saved integer state as valid.
   */
  old->valid = 1;

  /*
   * Inform the caller of the location of the last state saved.
   */
  *statep = (uintptr_t) oldThread;

  /*
   * Switch the CPU over to using the new set of interrupt contexts.  However,
   * don't change the stack pointer.
   */
  cpup->currentThread = newThread;

  /*
   * Now, reload the integer state pointed to by new.
   */
  if (new->valid) {
    /*
     * Verify that we can load the new integer state.
     */
    checkIntegerForLoad (new);

    /*
     * Switch the CPU over to using the new set of interrupt contexts.
     */
    cpup->currentThread = newThread;
    cpup->tssp->rsp0    = new->kstackp;
    cpup->tssp->ist3    = new->ist3;
    cpup->newCurrentIC  = new->currentIC;
    cpup->gip           = new->ifp;

    /*
     * If the new state uses secure memory, we need to map it into the page
     * table.  Note that we refetch the state information from the CPUState
     * to ensure that we're not accessing stale local variables.
     */
    if (vg && (newThread->secmemSize)) {
      /*
       * Get a pointer into the page tables for the secure memory region.
       */
      pml4e_t * secmemp = (pml4e_t *) getVirtual ((uintptr_t)(get_pagetable() + secmemOffset));

      /*
       * Restore the PML4E entry for the secure memory region.
       */
      uintptr_t mask = PTE_PRESENT | PTE_CANWRITE | PTE_CANUSER;
      if ((newThread->secmemPML4e & mask) != mask)
        panic ("SVA: Not Present: %lx %lx\n", newThread->secmemPML4e, mask);
      unprotect_paging ();
      *secmemp = newThread->secmemPML4e;
      protect_paging ();
    }

#ifdef SVA_LLC_PART
    if (vg && (oldThread->secmemSize) && (newThread->secmemSize) && (oldThread->secmemPML4e != newThread->secmemPML4e)) 
	    wbinvd();
#endif
    /*
     * Invalidate the state that we're about to load.
     */
    new->valid = 0;

    /*
     * Load the floating point state.
     */
#if 0
    /* No need to do this after the floating point optimization. */
    load_fp (&(new->fpstate));
#endif

    /*
     * Load the rest of the integer state.
     */
    load_integer (new);
  }

  /*
   * The context switch failed.
   */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_swap_integer_3_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return 0; 
}

/*
 * Intrinsic: sva_ialloca()
 *
 * Description:
 *  Allocate an object of the specified size on the current stack belonging to
 *  the most recent Interrupt Context and copy data into it.
 *
 * Inputs:
 *  size      - The number of bytes to allocate on the stack pointed to by the
 *              Interrupt Context.
 *  alignment - The power of two alignment to use for the memory object.
 *  initp     - A pointer to the data with which to initialize the memory
 *              object.  This is allowed to be NULL.
 *
 * NOTES:
 *  There is an issue with having sva_ialloca() copy data into the stack
 *  object.  The kernel uses copyout() to ensure that the memory is not part
 *  of kernel memory and can return EFAULT if the copy fails.  The question
 *  is how to make sva_ialloca() do the same thing.
 */
void *
sva_ialloca (uintptr_t size, uintptr_t alignment, void * initp) {
  uint64_t tsc_tmp;  
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();

  /* Old interrupt flags */
  uintptr_t rflags;

  /* Pointer to allocated memory */
  void * allocap = 0;

  /* Determine if an allocation is permitted */
  unsigned char allocaOkay = 1;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Get the most recent interrupt context and the current CPUState and
   * thread.
   */
  struct CPUState * cpup = getCPUState();
  sva_icontext_t * icontextp = cpup->newCurrentIC;

  /*
   * If the Interrupt Context was privileged, then don't do an ialloca.
   */
  allocaOkay &= !(sva_was_privileged());

  /*
   * Determine whether initp points within the secure memory region.  If it
   * does, then don't allocate anything.
   */
  if (vg) {
    allocaOkay &= isNotWithinSecureMemory (initp);
  }

  /*
   * Check if the alignment is within range.
   */
  allocaOkay &= (alignment < 64);

  /*
   * Only perform the ialloca() if the Interrupt Context represents user-mode
   * state.
   */
  if (allocaOkay) {
    /*
     * Mark the interrupt context as invalid.  We don't want it to be placed
     * back on to the processor until an sva_ipush_function() pushes a new stack
     * frame on to the stack.
     *
     * We do this by turning off the LSB of the valid field. 
     */
    icontextp->valid &= (~(IC_is_valid));

    /*
     * Perform the alloca.
     */
    allocap = icontextp->rsp;
    allocap -= size;

    /*
     * Align the pointer.
     */
    const uintptr_t mask = 0xffffffffffffffffu;
    allocap = (void *)((uintptr_t)(allocap) & (mask << alignment));

    /*
     * Verify that the stack pointer in the interrupt context is not within
     * kernel memory.
     */
    unsigned char spOkay = 1;
    if (isNotWithinSecureMemory(icontextp->rsp) &&
       ((((uintptr_t)allocap) >= 0xffffffff00000000u) ||
        ((((uintptr_t)allocap) + size) >= 0xffffffff00000000u))) {
      spOkay = 0;
    }

    /*
     * If the stack pointer is okay, go ahead and complete the operation.
     */
    if (spOkay) {
      /*
       * Fault in any necessary pages; the stack may be located in traditional
       * memory.
       */
      sva_check_memory_write (allocap, size);

      /*
       * Save the result back into the Interrupt Context.
       */
      icontextp->rsp = (unsigned long *) allocap;

      /*
       * Copy data in from the initializer.
       *
       * FIXME: This should use an invokememcpy() so that we know whether the
       *        address is valid.
       */
      if (initp)
        memcpy (allocap, initp, size);
    } else {
      allocap = 0;
    }
  }

  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();

  record_tsc(sva_ialloca_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return allocap;
}

/*
 * Intrinsic: sva_load_icontext()
 *
 * Description:
 *  This intrinsic takes state saved by the Execution Engine during an
 *  interrupt and loads it into the latest interrupt context.
 */
void
sva_load_icontext (void) {
  uint64_t tsc_tmp;  
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
 
  /* Old interrupt flags */
  uintptr_t rflags;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Get the most recent interrupt context and the current CPUState and
   * thread.
   */
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;
  sva_icontext_t * icontextp = cpup->newCurrentIC;

  /*
   * Verify that the interrupt context represents user-space state.
   */
  if (sva_was_privileged ()) {
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      record_tsc(sva_load_icontext_1_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
      return;
  }

  /*
   * Verify that we have a free interrupt context to use.
   */
  if (threadp->savedICIndex < 1) {
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      record_tsc(sva_load_icontext_2_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
      return;
  }

  /*
   * Load the interrupt context.
   */
  *icontextp = threadp->savedInterruptContexts[--(threadp->savedICIndex)];

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();

  record_tsc(sva_load_icontext_3_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Intrinsic: sva_save_icontext()
 *
 * Description:
 *  Save the most recent interrupt context into SVA memory so that it can be
 *  restored later.
 *
 * Return value:
 *  0 - An error occured.
 *  1 - No error occured.
 */
unsigned char
sva_save_icontext (void) {
  uint64_t tsc_tmp;  
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
 
 /* Old interrupt flags */
  uintptr_t rflags;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Get the most recent interrupt context and the current CPUState and
   * thread.
   */
  struct CPUState * cpup = getCPUState();
  struct SVAThread * threadp = cpup->currentThread;
  sva_icontext_t * icontextp = cpup->newCurrentIC;

  /*
   * Verify that the interrupt context represents user-space state.
   */
  if (sva_was_privileged ()) {
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      record_tsc(sva_save_icontext_1_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
      return 0;
  }

  /*
   * Verify that we have a free interrupt context to use.
   */
  if (threadp->savedICIndex > maxIC) {
      sva_exit_critical (rflags);
      usersva_to_kernel_pcid();
      record_tsc(sva_save_icontext_2_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
      return 0;
  }

  /*
   * Save the interrupt context.
   */
  threadp->savedInterruptContexts[threadp->savedICIndex] = *icontextp;

  /*
   * Increment the saved interrupt context index and save it in a local
   * variable.
   */
  unsigned char savedICIndex = ++(threadp->savedICIndex);

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);

  usersva_to_kernel_pcid();  

  record_tsc(sva_save_icontext_3_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return savedICIndex;
}

void
svaDummy (void) {
  panic ("SVA: svaDummy: Return to user space!\n");
  return;
}

/*
 * Intrinsic: sva_reinit_icontext()
 *
 * Description:
 *  Reinitialize an interrupt context so that, upon return, it begins to
 *  execute code at a new location.  This supports the exec() family of system
 *  calls.
 *
 * Inputs:
 *  transp - An identifier representing the entry point.
 *  priv   - A flag that, when set, indicates that the code will be executed in
 *           the processor's privileged mode.
 *  stack   - The value to set for the stack pointer.
 *  arg     - The argument to pass to the function entry point.
 */
void
sva_reinit_icontext (void * handle, unsigned char priv, uintptr_t stackp, uintptr_t arg) {
  uint64_t tsc_tmp;  
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
  /* Old interrupt flags */
  uintptr_t rflags;

  /* Function entry point */
  void * func = handle;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Validate the translation handle.
   */
  struct translation * transp = (struct translation *)(handle);
  if (vg) {
    if ((translations <= transp) && (transp < translations + 4096)) {
      if (((uint64_t)transp - (uint64_t)translations) % sizeof (struct translation)) {
        panic ("SVA: Invalid translation handle: %p %p %lx\n", transp, translations, sizeof (struct translation));
        usersva_to_kernel_pcid();
        record_tsc(sva_reinit_icontext_1_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
        return;
      }
    } else {
      panic ("SVA: Out of range translation handle: %p %p %lx\n", transp, translations, sizeof (struct translation));
      usersva_to_kernel_pcid();
      record_tsc(sva_reinit_icontext_2_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
      return;
    }

    if (transp->used != 2)
      panic ("SVA: Bad transp: %d\n", transp->used);

    /* Grab the function to call from the translation handle */
    func = transp->entryPoint;
  }

  /*
   * Get the most recent interrupt context.
   */
  struct SVAThread * threadp = getCPUState()->currentThread;
  sva_icontext_t * ep = getCPUState()->newCurrentIC;

  /*
   * Check the memory.
   */
  sva_check_memory_write (ep, sizeof (sva_icontext_t));

  /*
   * Remove mappings to the secure memory for this thread.
   */
  if (vg && (threadp->secmemSize)) {
    /*
     * Get a pointer into the page tables for the secure memory region.
     */
    pml4e_t * secmemp = (pml4e_t *) getVirtual ((uintptr_t)(get_pagetable() + secmemOffset));

    /*
     * Mark the secure memory is unmapped in the page tables.
     */
    unprotect_paging ();
    *secmemp = 0;
    protect_paging ();

    /*
     * Delete the secure memory mappings from the SVA thread structure.
     */
    threadp->secmemSize = 0;
    threadp->secmemPML4e = 0;

    /*
     * Flush the secure memory page mappings.
     */
    flushSecureMemory (threadp);
  }

  /*
   * Clear out saved FP state.
   */
  threadp->ICFPIndex = 1;

  /*
   * Commented the following to speed up. Part of the floating point
   * optimization.
   */
#if 0
  bzero (threadp->ICFP, sizeof (sva_fp_state_t));
#endif

  /*
   * Clear out any function call targets.
   */
  threadp->numPushTargets = 0;

  /*
   * Setup the call to the new function.
   */
  ep->rip = (uintptr_t) func;
  ep->rsp = (uintptr_t *)stackp;
  ep->rdi = arg;

  /*
   * Setup the segment registers for the proper mode.
   */
  if (priv) {
    panic ("SVA: sva_reinit_context: No support for creating kernel state.\n");
  } else {
    ep->cs = 0x43;
    ep->ss = 0x3b;
    ep->ds = 0x3b;
    ep->es = 0x3b;
    ep->fs = 0x13;
    ep->gs = 0x1b;
    ep->rflags = (rflags & 0xfffu);
  }

  /*
   * Now that ghost memory has been reinitialized, install the key for this
   * bitcode file into the ghost memory and then invalidate the translation
   * handle since we've now used it.
   */
  if (vg) {
    memcpy (&(threadp->ghostKey), &(transp->key), sizeof (sva_key_t));
    transp->used = 0;
  }

  /* Re-enable interupts if they were enabled before */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_reinit_icontext_3_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Intrinsic: sva_release_stack()
 *
 * Description:
 *  This intrinsic tells the virtual machine that the specified integer state
 *  should be discarded and that its stack is no longer a kernel stack.
 */
void
sva_release_stack (uintptr_t id) {
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();
 
  kernel_to_usersva_pcid();
 
  /* Get a pointer to the saved state (the ID is the pointer) */
  struct SVAThread * newThread = validateThreadPointer(id);
  if (! newThread) {
	 panic("sva_release_stack: Invalid thread pointer");
	 return;
  }

  sva_integer_state_t * new =  newThread ? &(newThread->integerState) : 0;

  /*
   * Ensure that we're not trying to release our own state.
   */
  if (newThread == getCPUState()->currentThread)
  {
    usersva_to_kernel_pcid();
    record_tsc(sva_release_stack_1_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
    return;
  }
  /*
   * Release ghost memory belonging to the thread that we are deallocating.
   */
  if (vg) {
    extern void
    ghostFree (struct SVAThread * tp, unsigned char * p, intptr_t size);
    unsigned char * secmemStart = (unsigned char *)(SECMEMSTART);
    ghostFree (newThread, secmemStart, newThread->secmemSize);
  }

  /*
   * Mark the integer state as invalid.  This will prevent it from being
   * context switched on to the CPU.
   */
  new->valid = 0;

  /*
   * Mark the thread as available for reuse.
   */
  newThread->used = 0;

  /* Push the thread into the stack of free threads since it can be reused */
  ftstack_push(newThread);
  usersva_to_kernel_pcid();
  record_tsc(sva_release_stack_2_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return;
}

/*
 * Intrinsic: sva_init_stack()
 *
 * Description:
 *  Pointer to the integer state identifier used for context switching.
 *
 * Inputs:
 *  start_stackp - A pointer to the *beginning* of the kernel stack.
 *  length       - Length of the kernel stack in bytes.
 *  new_cr3	 - The new process(thread)'s cr3
 *  func         - The kernel function to execute when the new integer state
 *                 is swapped on to the processor.
 *  arg          - The first argument to the function.
 *
 * Return value:
 *  An identifier that can be passed to sva_swap_integer() to begin execution
 *  of the thread.
 */
uintptr_t
sva_init_stack (unsigned char * start_stackp,
                uintptr_t length,
		uintptr_t new_cr3,
                void * func,
                uintptr_t arg1,
                uintptr_t arg2,
                uintptr_t arg3) {
 
  uint64_t tsc_tmp;
  if(tsc_read_enable_sva)
     tsc_tmp = sva_read_tsc();

  kernel_to_usersva_pcid();
 
  /* Working memory pointer */
  sva_icontext_t * icontextp;
  /* Working integer state */
  sva_integer_state_t * integerp;

  /* Function to use to return from system call */
  extern void sc_ret(void);

  /* Arguments allocated on the new stack */
  struct frame {
    /* Dummy return pointer ignored by load_integer() */
    void * dummy;

    /* Return pointer for the function frame */
    void * return_rip;
  } * args;

  /* Old interrupt flags */
  uintptr_t rflags;

  /* End of stack */
  unsigned char * stackp = 0;

  /* Length of Stack */
  uintptr_t stacklen = length;

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();
  
  /*
   * Find the last byte on the stack.
   */
  stackp = start_stackp + stacklen;

  /*
   * Verify that the stack is big enough.
   */
  if (stacklen < sizeof (struct frame)) {
    panic ("sva_init_stack: Invalid stacklen: %d!\n", stacklen);
  }

  /*
   * Verify that the function is a kernel function.
   */
  uintptr_t f = (uintptr_t)(func);
  if ((f <= SECMEMEND) || (*((unsigned int *)(f)) != CHECKLABEL)) {
    panic ("sva_init_stack: Invalid function %p\n", func);
  }

  /* Pointer to the current CPU State */
  struct CPUState * cpup = getCPUState();

  /*
   * Verify that no interrupts or traps have occurred (other than a system call
   * into the kernel).
   */
#if 0
  if (cpup->newCurrentIC < &(cpup->currentThread->interruptContexts[maxIC - 1]))
    panic ("Invalid IC!\n");
#endif

  /*
   * Get access to the old thread.
   */
  struct SVAThread * oldThread = cpup->currentThread;

  /*
   * Allocate a new SVA thread.
   */
  struct SVAThread * newThread = findNextFreeThread();


  /*
   * Verify that the memory has the proper access.
   */
  sva_check_memory_read  (oldThread, sizeof (struct SVAThread));
  sva_check_memory_write (newThread, sizeof (struct SVAThread));

  /*
   * Copy over the secure memory mappings from the old thread to the new
   * thread.
   */
  if (vg) {
    newThread->secmemSize = oldThread->secmemSize;
    newThread->secmemPML4e = oldThread->secmemPML4e;
  }

  /*
   * Copy over the valid list of push targets for sva_ipush().
   */
  if (oldThread->numPushTargets) {
    unsigned index = 0;
    newThread->numPushTargets = oldThread->numPushTargets;
    for (index = 0; index < oldThread->numPushTargets; ++index) {
      newThread->validPushTargets[index] = oldThread->validPushTargets[index];
    }
  }

  /*
   * Copy over the last saved interrupted FP state.
   */
#if 0
  /* No need to do the following after the floating point optimization.*/
  if (oldThread->ICFPIndex) {
    *(newThread->ICFP) = *(oldThread->ICFP + oldThread->ICFPIndex - 1);
    newThread->ICFPIndex = 1;
  }
#endif

  /*
   * Allocate the call frame for the call to the system call.
   */
  stackp -= sizeof (struct frame);
  args = (struct frame *)stackp;

  /*
   * Initialize the arguments to the system call.  Also setup the interrupt
   * context and return function pointer.
   */
  args->return_rip = sc_ret;

  /*
   * Initialze the integer state of the new thread of control.
   */
  integerp = &(newThread->integerState);
  integerp->rip = (uintptr_t) func;
  integerp->rdi = arg1;
  integerp->rsi = arg2;
  integerp->rdx = arg3;
  integerp->rsp = (uintptr_t *) stackp;
  integerp->cs  = 0x43;
  integerp->ss  = 0x3b;
  integerp->valid = 1;
  integerp->rflags = 0x202;
  integerp->cr3 = new_cr3;
#if 0
  integerp->ist3 = integerp->kstackp;
#endif
#if 1
  integerp->kstackp = (uintptr_t) stackp;
#endif
  integerp->fpstate.present = 0;

  /*
   * Initialize the interrupt context of the new thread.  Note that we use
   * the last IC.
   *
   * FIXME: The check on cpup->newCurrentIC is really a hack.  We should really
   *        fix the code to ensure that newCurrentIC is always set correctly
   *        and that the first interrupt context is at the end of the interrupt
   *        context list.
   */
  icontextp = integerp->currentIC = newThread->interruptContexts + maxIC - 1;
  *icontextp = *(cpup->newCurrentIC);
#if 0
  printf("Before set the return value to zero, check rax, rax = 0x%lx\n",icontextp->rax);
#endif  
  /*
   * Set the return value to zero.
   *
   * FIXME: This is a hack.  Ideally, the return value setting code should do
   *        this.
   */
  icontextp->rax = 0;

  /*
   * If the parent thread is an initial thread for this CPU, we always
   * permit it to create a new child process.  Otherwise, the existing
   * thread's Interrupt Context must have the fork bit set to create a new
   * child thread.
   *
   * When creating the child thread, disable its fork bit so that the child
   * cannot be duplicated.  Disable the fork bit in the parent thread's
   * Interrupt Context as well so that it cannot be duplicated multiple times
   * for a single call to fork().
   */
  if ((oldThread->isInitialForCPU) ||
      (cpup->newCurrentIC->valid & IC_can_fork)) {
    /* Mark the new Interrupt Context as valid */
    icontextp->valid |= IC_is_valid; 

    /* Disable the fork bit in both the old and new Interrupt Contexts. */
    icontextp->valid &= (~(IC_can_fork));
    cpup->newCurrentIC->valid &= (~(IC_can_fork));
  } else {
    /*
     * Print an error and then permit the child process to be created anyway.
     * This makes the error more of a warning since we allow the system to
     * continue executing anyway.
     */
    printf ("SVA: Error!  Kernel performing unauthorized fork()!\n");
    icontextp->valid |= IC_is_valid;
  }

  if(vg && (oldThread->secmemSize))
  {
    /* If the system call is fork or pdfork, COW on the ghost memory of the parent process;
     * If the system call is rfork and the flags indicate the child process will be 
     * a separate process and have its own address space, COW on the ghost memory of
     * the parent process*/	
    if((cpup->newCurrentIC->rax == 2) || (cpup->newCurrentIC->rax == 518) || \
       ((cpup->newCurrentIC->rax == 251) && (cpup->newCurrentIC->rdi & RFPROC) \
       && !(cpup->newCurrentIC->rdi & RFMEM)))	
      ghostmemCOW(oldThread, newThread);
  }
  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);
  usersva_to_kernel_pcid();
  record_tsc(sva_init_stack_api, ((uint64_t) sva_read_tsc() - tsc_tmp));
  return (unsigned long) newThread;
}

