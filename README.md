SVA: Secure Virtual Architecture
================================

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

Authors:
========
The file CREDITS.TXT lists individual authors of the SVA source code.

Source Code Layout:
===================
SVAOS:
  The source code for the SVA-OS run-time library that implements the SVA-OS
  instructions.

llvm:
  The source code for the modified version of LLVM used for compiling the
  SVA-OS run-time library and the FreeBSD kernel.

freebsd9_patch_r15130:
  A patch that will modify the FreeBSD 9.0 kernel source code to work on SVA.

How to Compile SVA:
-------------------

Give that $SRC_ROOT is the location of the SVA source code, do the following:

o Build the modified Clang/LLVM compiler
  o Create a sub-directory in which to compile LLVM.  Call this $LLVM_OBJ_ROOT.
  o cd $LLVM_OBJ_ROOT
  o $SRC_ROOT/llvm/configure --enable-targets=host
  o gmake

