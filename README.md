SVA: Secure Virtual Architecture
===============================

Introduction:
=============
This is the open-source release of the Secure Virtual Architecture (SVA).  SVA
creates an extended version of the LLVM IR that is capable of supporting a
commodity operating system kernel (such as FreeBSD and Linux).  By controlling
the expression of operating system code, SVA can reliably control operating
system kernel behavior through compiler instrumentation.

This release is the second version of SVA that works on 64-bit x86 systems and
supports FreeBSD 9.0.

License:
========
The file LICENSE.TXT describes the licenses under which the source code is
covered.

Source Code Layout:
===================
SVAOS:
  The source code for the SVA-OS run-time library that implements the SVA-OS
  instructions.

llvm:
  The source code for the modified version of LLVM used for compiling the
  SVA-OS run-time library and the FreeBSD kernel.

FreeBSD9:
  The source code for the FreeBSD 9.0 kernel and user-space.  The kernel has
  been ported to use SVA-OS.

