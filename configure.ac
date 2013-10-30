#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.50])
AC_INIT([ndnx-trace], [1.1.1], [susmit@cs.colostate.edu])
AC_CONFIG_SRCDIR([source/conf.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

AM_INIT_AUTOMAKE
AM_PROG_CC_C_O

#PKG_CHECK_MODULES([NDN], [libndn.a])


# Checks for header files.
AC_CHECK_LIB(ndn, main,,[AC_MSG_ERROR([lndn not found, refer to INSTALL if it is in non-standard location])])
AC_CHECK_LIB(crypto, main,,[AC_MSG_ERROR([lcrypto not found, refer to INSTALL if it is in non-standard location])])
AC_CHECK_LIB(pthread, main,,[AC_MSG_ERROR([lpthread not found, refer to INSTALL if it is in non-standard location])])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h pthread.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strrchr strstr])

AC_CONFIG_FILES([Makefile
				 source/Makefile])
AC_OUTPUT
