AC_PREREQ([2.69])
AC_INIT([minigc], [0.0.1], [Narihiro Nakamura <authornari@gmail.com>])
AM_INIT_AUTOMAKE([1.14])
AC_CONFIG_SRCDIR([minigc.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC

AC_EXEEXT

AC_CHECK_HEADERS([assert.h errno.h setjmp.h stdbool.h stdio.h \
                  stdlib.h string.h unistd.h], [],
                 [AC_MSG_ERROR(one of mandatory headers not found)])

AC_TYPE_SIZE_T

AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
