dnl
dnl Configure script for SVA
dnl
AC_INIT([SVA], [1.0], [jtcriswel@gmail.com])

dnl
dnl Define enable options for SVA-OS
dnl
AC_ARG_ENABLE([vg], [Enable Virtual Ghost], [AC_DEFINE([VG])], [])

dnl
dnl Include the command-line option to configure the targets used by LLVM
dnl
AC_ARG_ENABLE([targets], [], [], [])

dnl
dnl Specify header files that need to be configured by configure
dnl
AC_CONFIG_HEADERS([SVA/include/sva/config.h])

dnl
dnl Specify the files that will need to be configured
dnl
AC_CONFIG_FILES([make.conf])

dnl
dnl Configure the SVA LLVM compiler
dnl
AC_CONFIG_SUBDIRS([llvm])

dnl
dnl Generate the output of the configure script
dnl
AC_OUTPUT
