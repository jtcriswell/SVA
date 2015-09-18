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

Given that $SRC_ROOT is the location of the SVA source code, do the following:

o Build the modified Clang/LLVM compiler

  - Create a sub-directory in which to compile LLVM.  Call this $LLVM_OBJ_ROOT.

  - cd $LLVM_OBJ_ROOT

  - $SRC_ROOT/llvm/configure --enable-targets=host

  - gmake

o Build the SVA-OS run-time library

  - Change directory to the SVA subdirectory in the SVA source code

  - Compile the SVA-OS run-time library with the modified Clang/LLVM compiler:

  - make CC=$LLVM_OBJ_ROOT/Release+Asserts/bin/clang \
         CXX=$LLVM_OBJ_ROOT/Release+Asserts/bin/clang++ \
         CPP=$LLVM_OBJ_ROOTRelease+Asserts/bin/clang-cpp

o Download and extract the FreeBSD 9.0 source code:

  -  fetch ftp://ftp-archive.freebsd.org/pub/FreeBSD-Archive/old-releases/amd64/9.0-RELEASE/src.txz

  - xzcat src.gxz | tar -xvf -

o Apply the SVA patch to the FreeBSD source code

  - cd usr/src

  - patch -p0 < ../../freebsd9_patch_r15130

o Modify $SRC_ROOT/make.config so that

  - The CC variable is set to $LLVM_OBJ_ROOT/Release+Asserts/bin/clang -I$SRC_ROOT/SVA/include

  - The CXX variable is set to $LLVM_OBJ_ROOT/Release+Asserts/bin/clang++ -I$SRC_ROOT/SVA/include

  - The CPP variable is set to $LLVM_OBJ_ROOT/Release+Asserts/bin/clang-cpp -I$SRC_ROOT/SVA/include

  - The CFLAGS variable include the text -I$SRC_ROOT/SVA/include

o Build the kernel, setting INSTKERNNAME to the name of the kernel

  - make buildkernel INSTKERNNAME=svaKernel __MAKE_CONF=$SRC_ROOT/make.conf

o As the root user, install the kernel

  - make installkernel INSTKERNNAME=svaKernel __MAKE_CONF=$SRC_ROOT/make.conf

Incremental Kernel Compiles
---------------------------

Once the FreeBSD SVA kernel has been compiled, you can add the following
four lines in make.conf to avoid reconfiguring the kernel and to prevent the
kernel from being rebuilt from scratch:

NO_KERNELCLEAN=true
NO_KERNELCONFIG=true
NO_KERNELDEPEND=true
NO_KERNELOBJ=true

Note that the FreeBSD Makefiles do not detect when the SVA Clang compiler
has been modified.  If you modify the compiler, you will need to rebuild the
kernel from scratch.

Running the SVA FreeBSD Kernel
------------------------------
The SVA FreeBSD kernel only runs in single-user mode at present.  When booting,
exit to the boot loader prompt (option 2 by default in the FreeBSD boot
loader) and use "boot <kernelname> -s" to boot in single user mode.

