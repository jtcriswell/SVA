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

freebsd9_patch:
  A patch that will modify the FreeBSD 9.0 kernel source code to work on SVA.

autoconf:
  The source code to the AutoConf configure script.

How to Compile SVA:
-------------------

Given that $SRC_ROOT is the location of the SVA source code, do the following:

o Run the configure script in the source tree to create make.conf.  If you want
  to enable the Virtual Ghost features, add the --enable-vg option.

  - cd $SRC_ROOT

  - ./configure --enable-targets=host  --enable-vg

o Change directory to the llvm directory and Build the modified Clang/LLVM
  compiler.  Be sure to use GNU Make (gmake):

  - cd llvm ; gmake

o Change directory to the SVA-OS subdirectory and Build the SVA-OS run-time
  library

  - cd ../SVA ; make

o If you do not have write access to /usr/obj, create a directory for storing
  object files created during the kernel build and set the MAKEOBJDIRPREFIX
  variable to refer to this directory:

  - cd $SRC_ROOT ; mkdir obj

  - MAKEOBJDIRPREFIX=$SRC_ROOT/obj

o Download and extract the FreeBSD 9.0 source code:

  - fetch ftp://ftp-archive.freebsd.org/pub/FreeBSD-Archive/old-releases/amd64/9.0-RELEASE/src.txz

  - xzcat src.txz | tar -xvf -

o Apply the SVA patch to the FreeBSD source code

  - cd usr/src

  - patch -p1 < ../../freebsd9_patch

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
loader) and use "boot <kernelname> -s" to boot in single user mode.  The name
in the examples above is svaKernel.

