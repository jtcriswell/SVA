dnl
dnl Configure script for SVA
dnl
AC_INIT([SVA], [1.0], [jtcriswel@gmail.com])

dnl
dnl Include the command-line option to configure the targets used by LLVM
dnl
AC_ARG_ENABLE([targets], [], [], [])

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
