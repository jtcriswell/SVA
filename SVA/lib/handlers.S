/*===- handlers.S - SVA Execution Engine Assembly --------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===
 *
 * This is x86_64 assembly code used by the SVA Execution Engine.
 * It is in AT&T syntax, which means that the source operand is first and
 * the destination operand is second.
 *
 *===----------------------------------------------------------------------===
 */

/*****************************************************************************
 * Macros
 ****************************************************************************/

#include "offsets.h"
#include <sva/cfi.h>
#include <sva/asmconfig.h>

/* FreeBSD segment selector for kernel code segment */
#define USERCS 0x43

/*
 * Macro: TRAP
 *
 * Description:
 *  Create an assembly language routine that can dispatch the specified trap.
 *  This version is for traps that do not generate their own error code.
 */
#define TRAP(x) \
  .global trap##x ; \
  .type   trap##x, @function ; \
; \
trap##x: \
  /* Adjust the stack pointer so that we can push items using %ds */ \
  subq $16, %rsp ; \
 \
  /* Push a zero code */ \
  movq $0, 8(%rsp) ; \
\
  /* Push the trap number */ \
  movq $x, 0(%rsp) ; \
\
  /* Determine whether we interrupted user or supervisor mode execution. */ \
  cmpq $USERCS, 24(%rsp) ; \
  jne 1f ; \
 \
  /* We came from user mode.  First switch to the kernel %GS register. */ \
  swapgs ; \
1: \
  /* Call the common trap code. */ \
  jmp Trap

/*
 * Macro: ECTRAP
 *
 * Description:
 *  Create an assembly language routine that can dispatch the specified trap.
 *  This version is for traps that generate their own error code.
 */
#define ECTRAP(x) \
  .global trap##x ; \
  .type   trap##x, @function ; \
; \
trap##x: \
  /* Adjust the stack pointer so that we can push items using %ds */ \
  subq $8, %rsp ; \
 \
  /* Push the trap number */ \
  movq $x, 0(%rsp) ; \
\
  /* Determine whether we interrupted user or supervisor mode execution. */ \
  cmpq $USERCS, 24(%rsp) ; \
  jne 1f ; \
 \
  /* We came from user mode.  First switch to the kernel %GS register. */ \
  swapgs ; \
1: \
 \
  /* Call the common trap code. */ \
  jmp Trap

/*
 * Macro: INTERRUPT()
 * 
 * Description:
 *  Define the handler for an interrupt.  This is nearly identical to the 
 *  trap code.  It is really only different because it was different in the
 *  original SVA system; the new system does not need to distinguish between
 *  an interrupt and a trap.
 */
#define INTERRUPT(x) \
  .global interrupt##x ; \
  .type   interrupt##x, @function ; \
; \
interrupt##x: \
  /* Adjust the stack pointer so that we can push items using %ds */ \
  subq $16, %rsp ; \
 \
  /* Push a zero code */ \
  movq $0, 8(%rsp) ; \
\
  /* Push the trap number */ \
  movq $x, 0(%rsp) ; \
\
  /* Determine whether we interrupted user or supervisor mode execution. */ \
  cmpq $USERCS, 24(%rsp) ; \
  jne 1f ; \
 \
  /* We came from user mode.  First switch to the kernel %GS register. */ \
  swapgs ; \
1: \
 \
  /* Call the common trap code. */ \
  jmp Trap

/*****************************************************************************
 * Data Section
 ****************************************************************************/
.data
.comm interrupt_table, 2048

/*****************************************************************************
 * Text Section
 ****************************************************************************/
.text

.global SVAbadtrap
.type SVAbadtrap, @function

.global SVAsyscall
.type SVAsyscall, @function

.global sc_ret
.type   sc_ret, @function

.global secmemtrap
.type secmemtrap, @function

.global secfreetrap
.type secfreetrap, @function

.global sva_syscall
.type sva_syscall, @function

/*
 * Function: SVAbadtrap
 *
 * Description:
 *  This function just generates a fault, allowing us to catch traps which SVA
 *  isn't fielding.
 */
SVAbadtrap:
  /* Cause a breakpoint */
  sti
  int $0x03

  /* Return from the interrupt */
  iretq

/*
 * Function: Trap
 *
 * Description:
 *  This code is common code for all trap and interrupt handlers.
 *
 * Preconditions:
 *  o The GS register should be pointing to the base of the interrupt context
 *    for the current processor.
 *  o The error code and trap number should have been pushed on to the stack. 
 */
Trap:
  /*
   * Switch to the stack segment.
   */
  movq %rax, %gs:0x268
  movw $0x28, %ax
  movw %ax, %ss
  movq %gs:0x268, %rax

  /*
   * Allocate space for the SVA Interrupt Context.  Note that the hardware
   * has already created part of the Interrupt Context, so we only need to
   * allocate space for the fields not saved by the hardware.
   */
  subq $IC_TRSIZE, %rsp

  /*
   * Save a copy of the interrupt context into SVA memory.
   */
  movq %rbp, IC_RBP(%rsp)
  movq %r15, IC_R15(%rsp)
  movq %r14, IC_R14(%rsp)
  movq %r13, IC_R13(%rsp)
  movq %r12, IC_R12(%rsp)
  movq %r11, IC_R11(%rsp)
  movq %r10, IC_R10(%rsp)
  movq %r9,  IC_R9(%rsp)
  movq %r8,  IC_R8(%rsp)

  movq %rdx, IC_RDX(%rsp)
  movq %rcx, IC_RCX(%rsp)
  movq %rbx, IC_RBX(%rsp)
  movq %rax, IC_RAX(%rsp)

  movq %rsi, IC_RSI(%rsp)
  movq %rdi, IC_RDI(%rsp)

  /* Save the segment registers */
  movw %ds, %ax
  movw %es, %bx
  movw %fs, %cx
  movw %gs, %dx
  movw %ax, IC_DS(%rsp)
  movw %bx, IC_ES(%rsp)
  movw %cx, IC_FS(%rsp)
  movw %dx, IC_GS(%rsp)

  /* Push the invoke frame pointer */
  movq $0, IC_INVOKEP(%rsp)

  /* Flag the interrupt context as valid */
  movq $1, IC_VALID(%rsp)

  /*
   * Configure the process to trigger a floating point fault while in
   * kernel mode.  This requires disabling the EM bit and enabling the MP and
   * TS bits in CR0.
   *
   * Record that no floating point state is saved (it is saved lazily).
   */
  movq %gs:0x260, %rbp
  testq $1, CPU_FPUSED(%rbp)
  jne 1f
  movq %cr0, %rsi
  andl $0xfffffffb, %esi
  orq  $0x0a, %rsi
  movq %rsi, %cr0
  movq $0, CPU_FPUSED(%rbp)
1:
  movq $0, IC_FPP(%rsp)

  /*
   * Save the address of the current interrupt context into this processor's
   * CPU state.
   */
  movq %rsp, CPU_NEWIC(%rbp)

  /*
   * Move the trap number into the %rdi register.
   */
  movq IC_TRAPNO(%rsp), %rdi

  /*
   * Move the address causing the fault (which may or may not be applicable)
   * into the %rsi register to make it the second argument.
   */
  movq %cr2, %rsi

#if 0 
  /* Verify the Interrupt Context */
  callq assertGoodIC
  RETTARGET
#endif

  /*
   * Modify the value in the Task State Segment (TSS) so that the next trap
   * or interrupt on this processor saves state into the next interrupt
   * context.
   */
  movq CPU_TSSP(%rbp), %rbx
  movq %rsp, TSS_IST3(%rbx)

  /*
   * Adjust it to point to the first byte of the current interrupt context.
   */
  subq $0x10, TSS_IST3(%rbx)

  /*
   * Switch to the kernel stack.  If coming from user space, use the kernel
   * stack pointer specified by the kernel.  Otherwise, use the previous
   * kernel stack pointer.
   *
   * NOTE: The offset to the code segment is hard-coded here because I couldn't
   *       get the macro magic working properly.  If the interrupt context
   *       layout changes, the offset used to look for the code segment will
   *       also need to change.
   */
  cmpq $USERCS, 0xa0(%rsp)
  cmoveq 4(%rbx), %rsp
  cmovneq IC_RSP(%rsp), %rsp

  /*
   * Zero out live registers that could be spilled to the stack.  Without
   * memory safety, we can't guarantee that they're safe.
   *
   * We can leave the FP/SSE registers alone.  A read or write of those
   * registers will cause a floating point trap.  The SVA FP trap handler
   * will lazily save the floating point state and load the missing floating
   * point state.
   */
#ifdef VG
  xorq %r15, %r15
  xorq %r14, %r14
  xorq %r13, %r13
  xorq %r12, %r12
  xorq %r11, %r11
  xorq %r10, %r10
  xorq %r9,  %r9
  xorq %r8,  %r8
  xorq %rdx, %rdx
  xorq %rcx, %rcx
#endif

  /*
   * Call the trap handler registered by the OS for this trap.
   */
  movq $interrupt_table, %rax
  callq *(%rax,%rdi,8)
  RETTARGET

  /*
   * Disable interrupts.
   */
  cli

  /*
   * Switch the stack pointer back to the interrupt context.
   */
  movq %gs:0x260, %rbp
  movq CPU_NEWIC(%rbp), %rsp

  /*
   * Verify that the interrupt context is valid (e.g., no sva_ialloca has been
   * performed without a subsequent sva_ipush_function).
   */
  movq $1, %rdi
  testq $1, IC_VALID(%rsp)
  je invalidIC

  /*
   * Pop off the most recent interrupt context.  This requires modifying
   * the newCurrentIC field of the CPUState as well as modifying the IST
   * in the TSS.
   */
  addq $IC_SIZE, CPU_NEWIC(%rbp)
  movq CPU_TSSP(%rbp), %rbx
  addq $IC_SIZE, TSS_IST3(%rbx)

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  movw IC_FS(%rsp), %ax
  movw IC_ES(%rsp), %bx
  movw IC_DS(%rsp), %cx
  movw %ax, %fs
  movw %bx, %es
  movw %cx, %ds

  movq IC_RDI(%rsp), %rdi
  movq IC_RSI(%rsp), %rsi

  movq IC_RAX(%rsp), %rax
  movq IC_RBX(%rsp), %rbx
  movq IC_RCX(%rsp), %rcx
  movq IC_RDX(%rsp), %rdx

  movq  IC_R8(%rsp), %r8
  movq  IC_R9(%rsp), %r9
  movq IC_R10(%rsp), %r10
  movq IC_R11(%rsp), %r11
  movq IC_R12(%rsp), %r12
  movq IC_R13(%rsp), %r13
  movq IC_R14(%rsp), %r14
  movq IC_R15(%rsp), %r15
  movq IC_RBP(%rsp), %rbp

  /*
   * Remove the current interrupt context.
   */
  addq $0x98, %rsp

  /* Determine whether we interrupted user or supervisor mode execution. */
  cmpq $USERCS, 8(%rsp)
  jne 1f

  /* We came from user mode.  First switch to the kernel %GS register. */
  swapgs

1:
  /*
   * Return to the calling code.  On x86_64, this will restore the stack
   * pointer regardless of whether we came from user mode or kernel mode.
   */
  iretq

/*
 * Trap: SVAsyscall
 *
 * Description:
 *  This trap handles system call entry.
 *
 * Preconditions:
 *  o The GS register should be pointing to the base of the interrupt context
 *    for the current processor.
 *
 * Notes:
 *  o This function is called by the processor by the syscall instruction.
 *    When we enter, we are still running on the application's stack.
 *
 *  o We assume that the syscall instruction was executed in user-mode.  SVA
 *    should ensure that syscall is never generated for kernel code and that
 *    the kernel cannot jump to user-space code containing the syscall
 *    sequence.
 *
 *  o The SVA CFI checks should prevent the kernel from jumping to a syscall
 *    instruction that exists in kernel code because it will violate the
 *    assumption that we need to use swapgs to configure the %GS register.
 */
SVAsyscall:
  /* ENSURE that interrupts are disabled */
  cli

  /* We came from user mode.  First switch to the kernel %GS register. */
  swapgs

  /*
   * Save the stack pointer (%rsp) and frame pointer (%rbp) of the application.
   */
  movq %rsp, %gs:0x268
  movq %rbp, %gs:0x270

  /*
   * Get the location of the Interrupt Context within the current thread and
   * make the stack pointer point to it.
   */
  movq %gs:0x260, %rbp
  movq CPU_TSSP(%rbp), %rbp
  movq TSS_IST3(%rbp), %rsp
  addq $0x10, %rsp

  /* Initialize the floating point state pointer to NULL */
  pushq $0

  /* Mark the Interrupt Context as valid */
  pushq $1

  /* Set the stack segment register to zero */
  pushq $0

  /* Push the user-space stack pointer (%rsp) */
  pushq %gs:0x268

  /* Push the user-space status flags */
  pushq %r11

  /* Push the user-space code segment */
  pushq $USERCS

  /* Push the user-space program counter (%rip) */
  pushq %rcx

  /* Push a zero code */
  pushq $0

  /* Push a dummy trap number */
  pushq $0

  /*
   * Save a copy of the interrupt context into SVA memory.
   */
  pushq %gs:0x270
  pushq %r15
  pushq %r14
  pushq %r13
  pushq %r12
  pushq %r11
  pushq %r10
  pushq %r9
  pushq %r8

  pushq %rdx
  pushq %rcx
  pushq %rbx
  pushq %rax

  pushq %rsi
  pushq %rdi

  movw %ds, %ax
  movw %es, %bx
  pushw %ax
  pushw %bx
  pushw %gs
  pushw %fs

  /* Push a NULL invoke pointer into the Interrupt Context */
  pushq $0

  /*
   * Mark the interrupt context as valid.  Additionally, set the fork bit
   * if this is the fork(), vfork(), rfork(), or pdfork() system calls.  The
   * system call number will be in %rax and can have the following values
   * (you can find these in syscalls.master) within the FreeBSD kernel source
   * code):
   *
   *   2 - fork()
   *  66 - vfork()
   * 251 - rfork()
   * 518 - pdfork()
   */
  movq $1, %r12
  movq $3, %r13
  cmpq $2, IC_RAX(%rsp)
  cmoveq %r13, %r12
  cmpq $66, IC_RAX(%rsp)
  cmoveq %r13, %r12
  cmpq $251, IC_RAX(%rsp)
  cmoveq %r13, %r12
  cmpq $518, IC_RAX(%rsp)
  cmoveq %r13, %r12
  movq %r12, IC_VALID(%rsp)

  /*
   * Configure the process to trigger a floating point fault while in
   * kernel mode.  This requires disabling the EM bit and enabling the MP and
   * TS bits in CR0.
   *
   * Record that no floating point state is saved (it is saved lazily).
   */
  movq %gs:0x260, %rbp
  testq $1, CPU_FPUSED(%rbp)
  jne 1f
  movq %cr0, %rsi
  andl $0xfffffffb, %esi
  orq  $0x0a, %rsi
  movq %rsi, %cr0
  movq $0, CPU_FPUSED(%rbp)
1:
  movq $0, IC_FPP(%rsp)

  /*
   * Save the address of the current interrupt context into this processor's
   * CPU state.
   */
  movq %rsp, CPU_NEWIC(%rbp)
  
  /*
   * Modify the value in the Task State Segment (TSS) so that the next trap
   * or interrupt on this processor saves state into the next interrupt
   * context.
   */
#if 1 
  /*
   * Adjust the stack pointer to point to the first byte of the current
   * interrupt context before storing it into the TSS.  Restore it when
   * we're done.
   */
  subq $0x10, %rsp
  movq CPU_TSSP(%rbp), %rbx
  movq %rsp, TSS_IST3(%rbx)
  addq $0x10, %rsp
#else
  movq CPU_TSSP(%rbp), %rbx
  subq $IC_SIZE, TSS_IST3(%rbx)
#endif

  /*
   * Switch to the kernel stack.  Since we always come from user space, 
   * switch to the kernel stack pointer specified by the kernel.
   */
  movq TSS_RSP0(%rbx), %rsp

  /*
   * Zero out live registers that could be spilled to the stack.  Without
   * memory safety, we can't guarantee that they're safe.
   *
   * We can leave the FP/SSE registers alone.  A read or write of those
   * registers will cause a floating point trap.  The SVA FP trap handler
   * will lazily save the floating point state and load the missing floating
   * point state.
   */
#ifdef VG
  xorq %r15, %r15
  xorq %r14, %r14
  xorq %r13, %r13
  xorq %r12, %r12
  xorq %r11, %r11
  xorq %r10, %r10
  xorq %rdi, %rdi
#endif

  /*
   * Call the system software system call handler.
   */
  callq sva_syscall
sc_ret:
  RETTARGET

  /*
   * Disable interrupts.
   */
  cli

  /*
   * Switch the stack pointer back to the interrupt context.
   */
  movq %gs:0x260, %rbp
  movq CPU_NEWIC(%rbp), %rsp

  /*
   * Verify that the interrupt context is valid (e.g., no sva_ialloca has been
   * performed without a subsequent sva_ipush_function).
   */
  movq $0, %rdi
  testq $1, IC_VALID(%rsp)
  je invalidIC

  /*
   * Pop off the most recent interrupt context.  This requires modifying
   * the newCurrentIC field of the CPUState as well as modifying the IST
   * in the TSS.
   */
  addq $IC_SIZE, CPU_NEWIC(%rbp)
  movq CPU_TSSP(%rbp), %rbx
  addq $IC_SIZE, TSS_IST3(%rbx)

  /*
   * Copy the registers from the interrupt context back on to the processor.
   */
  movw IC_FS(%rsp), %cx
  movw IC_ES(%rsp), %bx
  movw IC_DS(%rsp), %ax
  movw %cx, %fs
  movw %bx, %es
  movw %ax, %ds

  movq IC_RDI(%rsp), %rdi
  movq IC_RSI(%rsp), %rsi

  movq IC_RAX(%rsp), %rax
  movq IC_RBX(%rsp), %rbx
  movq IC_RIP(%rsp), %rcx   /* Put the %rip in %rcx for sysret instruction */
  movq IC_RDX(%rsp), %rdx

  movq  IC_R8(%rsp), %r8
  movq  IC_R9(%rsp), %r9
  movq IC_R10(%rsp), %r10
  movq IC_RFLAGS(%rsp), %r11 /* Put the rflags back into %r11 for sysret */
  movq IC_R12(%rsp), %r12
  movq IC_R13(%rsp), %r13
  movq IC_R14(%rsp), %r14
  movq IC_R15(%rsp), %r15
  movq IC_RBP(%rsp), %rbp

  /*
   * Restore the user-space stack pointer.
   */
  movq IC_RSP(%rsp), %rsp

  /* We came from user mode.  First switch to the kernel %GS register. */
  swapgs

  /*
   * Return to the calling code.
   */
  sysretq

/* Define the trap handlers */
TRAP(0)
TRAP(1)
TRAP(2)
TRAP(3)
TRAP(4)
TRAP(5)
TRAP(6)
TRAP(7)
ECTRAP(8)
TRAP(9)
ECTRAP(10)
ECTRAP(11)
ECTRAP(12)
ECTRAP(13)
ECTRAP(14)
TRAP(15)
TRAP(16)
ECTRAP(17)
TRAP(18)
TRAP(19)
TRAP(20)
TRAP(21)
TRAP(22)
TRAP(23)
TRAP(24)
TRAP(25)
TRAP(26)
TRAP(27)
TRAP(28)
TRAP(29)
TRAP(30)
TRAP(31)

/* Register all interrupts */
INTERRUPT(32)
INTERRUPT(33)
INTERRUPT(34)
INTERRUPT(35)
INTERRUPT(36)
INTERRUPT(37)
INTERRUPT(38)
INTERRUPT(39)
INTERRUPT(40)
INTERRUPT(41)
INTERRUPT(42)
INTERRUPT(43)
INTERRUPT(44)
INTERRUPT(45)
INTERRUPT(46)
INTERRUPT(47)
INTERRUPT(48)
INTERRUPT(49)
INTERRUPT(50)
INTERRUPT(51)
INTERRUPT(52)
INTERRUPT(53)
INTERRUPT(54)
INTERRUPT(55)
INTERRUPT(56)
INTERRUPT(57)
INTERRUPT(58)
INTERRUPT(59)
INTERRUPT(60)
INTERRUPT(61)
INTERRUPT(62)
INTERRUPT(63)
INTERRUPT(64)
INTERRUPT(65)
INTERRUPT(66)
INTERRUPT(67)
INTERRUPT(68)
INTERRUPT(69)
INTERRUPT(70)
INTERRUPT(71)
INTERRUPT(72)
INTERRUPT(73)
INTERRUPT(74)
INTERRUPT(75)
INTERRUPT(76)
INTERRUPT(77)
INTERRUPT(78)
INTERRUPT(79)
INTERRUPT(80)
INTERRUPT(81)
INTERRUPT(82)
INTERRUPT(83)
INTERRUPT(84)
INTERRUPT(85)
INTERRUPT(86)
INTERRUPT(87)
INTERRUPT(88)
INTERRUPT(89)
INTERRUPT(90)
INTERRUPT(91)
INTERRUPT(92)
INTERRUPT(93)
INTERRUPT(94)
INTERRUPT(95)
INTERRUPT(96)
INTERRUPT(97)
INTERRUPT(98)
INTERRUPT(99)
INTERRUPT(100)
INTERRUPT(101)
INTERRUPT(102)
INTERRUPT(103)
INTERRUPT(104)
INTERRUPT(105)
INTERRUPT(106)
INTERRUPT(107)
INTERRUPT(108)
INTERRUPT(109)
INTERRUPT(110)
INTERRUPT(111)
INTERRUPT(112)
INTERRUPT(113)
INTERRUPT(114)
INTERRUPT(115)
INTERRUPT(116)
INTERRUPT(117)
INTERRUPT(118)
INTERRUPT(119)
INTERRUPT(120)
INTERRUPT(121)
INTERRUPT(122)
TRAP(123) /* Get Random Thread ID Trap */
TRAP(124) /* Get Thread Secret Trap */
TRAP(125) /* Install Push Target Trap */
TRAP(126) /* Secure Memory Free Trap */
TRAP(127) /* Secure Memory Allocation Trap */
INTERRUPT(128)
INTERRUPT(129)
INTERRUPT(130)
INTERRUPT(131)
INTERRUPT(132)
INTERRUPT(133)
INTERRUPT(134)
INTERRUPT(135)
INTERRUPT(136)
INTERRUPT(137)
INTERRUPT(138)
INTERRUPT(139)
INTERRUPT(140)
INTERRUPT(141)
INTERRUPT(142)
INTERRUPT(143)
INTERRUPT(144)
INTERRUPT(145)
INTERRUPT(146)
INTERRUPT(147)
INTERRUPT(148)
INTERRUPT(149)
INTERRUPT(150)
INTERRUPT(151)
INTERRUPT(152)
INTERRUPT(153)
INTERRUPT(154)
INTERRUPT(155)
INTERRUPT(156)
INTERRUPT(157)
INTERRUPT(158)
INTERRUPT(159)
INTERRUPT(160)
INTERRUPT(161)
INTERRUPT(162)
INTERRUPT(163)
INTERRUPT(164)
INTERRUPT(165)
INTERRUPT(166)
INTERRUPT(167)
INTERRUPT(168)
INTERRUPT(169)
INTERRUPT(170)
INTERRUPT(171)
INTERRUPT(172)
INTERRUPT(173)
INTERRUPT(174)
INTERRUPT(175)
INTERRUPT(176)
INTERRUPT(177)
INTERRUPT(178)
INTERRUPT(179)
INTERRUPT(180)
INTERRUPT(181)
INTERRUPT(182)
INTERRUPT(183)
INTERRUPT(184)
INTERRUPT(185)
INTERRUPT(186)
INTERRUPT(187)
INTERRUPT(188)
INTERRUPT(189)
INTERRUPT(190)
INTERRUPT(191)
INTERRUPT(192)
INTERRUPT(193)
INTERRUPT(194)
INTERRUPT(195)
INTERRUPT(196)
INTERRUPT(197)
INTERRUPT(198)
INTERRUPT(199)
INTERRUPT(200)
INTERRUPT(201)
INTERRUPT(202)
INTERRUPT(203)
INTERRUPT(204)
INTERRUPT(205)
INTERRUPT(206)
INTERRUPT(207)
INTERRUPT(208)
INTERRUPT(209)
INTERRUPT(210)
INTERRUPT(211)
INTERRUPT(212)
INTERRUPT(213)
INTERRUPT(214)
INTERRUPT(215)
INTERRUPT(216)
INTERRUPT(217)
INTERRUPT(218)
INTERRUPT(219)
INTERRUPT(220)
INTERRUPT(221)
INTERRUPT(222)
INTERRUPT(223)
INTERRUPT(224)
INTERRUPT(225)
INTERRUPT(226)
INTERRUPT(227)
INTERRUPT(228)
INTERRUPT(229)
INTERRUPT(230)
INTERRUPT(231)
INTERRUPT(232)
INTERRUPT(233)
INTERRUPT(234)
INTERRUPT(235)
INTERRUPT(236)
INTERRUPT(237)
INTERRUPT(238)
INTERRUPT(239)
INTERRUPT(240)
INTERRUPT(241)
INTERRUPT(242)
INTERRUPT(243)
INTERRUPT(244)
INTERRUPT(245)
INTERRUPT(246)
INTERRUPT(247)
INTERRUPT(248)
INTERRUPT(249)
INTERRUPT(250)
INTERRUPT(251)
INTERRUPT(252)
INTERRUPT(253)
INTERRUPT(254)
INTERRUPT(255)
