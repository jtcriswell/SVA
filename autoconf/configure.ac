dnl
dnl Configure script for SVA
dnl
AC_INIT([SVA], [1.0], [jtcriswel@gmail.com])

dnl
dnl Define enable options for SVA-OS
dnl

dnl Enable the Virutal Ghost features
AC_ARG_ENABLE(vg,
              AS_HELP_STRING([--enable-vg],
                             [Enable Virtual Ghost (default is NO)]),
                             [case "${enableval}" in
                             	yes) AC_DEFINE(VG) ;;
                             	no)  AC_DEFINE(NOVG) ;;
                             	*)   AC_MSG_ERROR([bad value ${enableval} for --enable-vg]) ;;
                             esac],
                             AC_DEFINE(NOVG))

dnl Enable the SVA MMU Checks
AC_ARG_ENABLE(mmuchecks,
              AS_HELP_STRING([--enable-mmuchecks],
                             [Enable SVA MMU Checks (default is YES)]),
                             [case "${enableval}" in
                             	yes) AC_DEFINE(CHECKMMU) ;;
                             	no)  AC_DEFINE(NOCHECKMMU) ;;
                             	*)   AC_MSG_ERROR([bad value ${enableval} for --enable-mmuchecks]) ;;
                             esac],
                             AC_DEFINE(CHECKMMU))

dnl
dnl Include the command-line option to configure the targets used by LLVM
dnl
AC_ARG_ENABLE([targets], [], [], [])

dnl
dnl Specify header files that need to be configured by configure
dnl
AC_CONFIG_HEADERS([SVA/include/sva/asmconfig.h])

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
