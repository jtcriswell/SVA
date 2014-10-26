/*===- invoke.c - SVA Execution Engine  ----------------------------------===
 * 
 *                     The LLVM Compiler Infrastructure
 *
 * This file was developed by the LLVM research group and is distributed under
 * the GNU General Public License Version 2. See the file named COPYING for
 * details.  Note that the code is provided with no warranty.
 *
 * Copyright 2006-2009 University of Illinois.
 * Portions Copyright 1997 Andi Kleen <ak@muc.de>.
 * Portions Copyright 1997 Linus Torvalds.
 * 
 *===----------------------------------------------------------------------===
 *
 * The code from the Linux kernel was brought in and modified on 2006/05/09.
 * The code was primarily used for its fast strncpy() and strnlen()
 * implementations; the code for handling MMU faults during the memory
 * operations were modified for sva_invokestrncpy() and possibly modified for
 * sva_invokestrnlen().
 *
 *===----------------------------------------------------------------------===
 *
 * This is the code for the SVA Execution Engine that manages invoke/unwind
 * functionality.
 *
 *===----------------------------------------------------------------------===
 */

#include <sva/state.h>
#include <sva/util.h>

#include "offsets.h"

/*
 * Intrinsic: sva_unwind ()
 *
 * Description:
 *  Unwind the stack specifed by the interrupt context.
 */
void
sva_iunwind (void) {
  /* Current processor status flags */
  uintptr_t rflags;

  /* Assembly code that finishes the unwind */
  extern void sva_invoke_except(void);
  extern void sva_memcpy_except(void);

  /*
   * Disable interrupts.
   */
  rflags = sva_enter_critical();

  /*
   * Get the pointer to the most recent invoke frame and interrupt context.
   */
  struct CPUState * cpup    = getCPUState();
  struct invoke_frame * gip = cpup->gip;
  sva_icontext_t * ip       = cpup->newCurrentIC;

  /*
   * Do nothing if there is no invoke stack.
   */
  if (!gip) {
    /*
     * Re-enable interrupts.
     */
    sva_exit_critical (rflags);
    return;
  }

  /*
   * Check the invoke frame for read access.
   */
  sva_check_memory_read (gip, sizeof (struct invoke_frame));

  /*
   * Check the interrupt context pointer for write access.
   */
  sva_check_memory_write (ip, sizeof (sva_icontext_t));

  /*
   * Adjust the program state so that it resumes inside the invoke instruction.
   */
  switch (gip->cpinvoke) {
    case INVOKE_NORMAL:
      ip->rip = sva_invoke_except;
      break;

#if 0
    case INVOKE_MEMCPY_W:
      ip->rcx = (ip->rcx) << 2;
    case INVOKE_MEMCPY_B:
#endif
    case INVOKE_STRNCPY:
      ip->rip = (void *)(gip->rbx);
      break;

    default:
      panic ("SVA: Other Invoke Frames Unsupported!\n");
      break;
  }

  /*
   * Re-enable interrupts.
   */
  sva_exit_critical (rflags);
  return;
}

/*
 * Intrinsic: sva_invokestrncpy()
 *
 * Description:
 *  Copy a zero terminated string from one location to another.
 *
 * Inputs:
 *  dst   - The destination string.  It cannot overlap src.
 *  src   - The source string
 *  count - The maximum number of bytes to copy.
 *
 * Outputs:
 *  dst   - The destination string
 *
 * Return value:
 *  Return the number of bytes copied (not counting the string terminator),
 *  or -1 if a fault occurred.
 *
 * NOTE:
 *  This function contains inline assembly code from the original i386 Linux
 *  2.4.22 kernel code.  I believe it originates from the
 *  __do_strncpy_from_user() macro in arch/i386/lib/usercopy.c.
 *
 * TODO:
 *  It is not clear whether this version will be as fast as the x86_64 version
 *  in FreeBSD 9.0; this version is an x86_64 port of the original Linux 2.4.22
 *  code for 32-bit processors.
 */
uintptr_t
sva_invokestrncpy (char * dst, const char * src, uintptr_t count) {
  /* The invoke frame placed on the stack */
  struct invoke_frame frame;

  /* Return value */
  uintptr_t ret = 0;

  /* Other variables */
  uintptr_t res;
  uintptr_t __d0, __d1, __d2;

  /*
   * Determine if there is anything to copy.  If not, then return now.
   */
  if (count == 0)
    return 0;

  /*
   * Get the pointer to the most recent invoke frame.
   */
  struct CPUState * cpup    = getCPUState();
  struct invoke_frame * gip = cpup->gip;

  /* Mark the frame as being used for a memcpy */
  frame.cpinvoke = INVOKE_STRNCPY;
  frame.next = gip;

  /* Make it the top invoke frame */
  cpup->gip = &frame;

  /* Perform the strncpy */
  __asm__ __volatile__(
    " movq $2f, %5\n"
    "0: lodsb\n"
    " stosb\n"
    " testb %%al,%%al\n"
    " jz 1f\n"
    " decq %1\n"
    " jnz 0b\n"
    " jmp 1f\n"
    "2: movq $0xffffffffffffffff, %0\n"
    " jmp 3f\n"
    "1: subq %1,%0\n"
    "3:\n"
    : "=d"(res), "=c"(count), "=&a" (__d0), "=&S" (__d1),
      "=&D" (__d2), "=m" (frame.rbx)
    : "i"(0), "0"(count), "1"(count), "3"(src), "4"(dst)
    : "memory");

  /*
   * Pop off the invoke frame.
   */
  cpup->gip = frame.next;
  return res;
}

