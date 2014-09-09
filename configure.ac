AC_PREREQ([2.69])
AC_INIT([T+A DCP], [0.1], [r.tiemann@ta-hifi.com])
AM_INIT_AUTOMAKE([1.11 -Wall -Werror silent-rules foreign])
AC_CONFIG_SRCDIR([dcpd.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_CHECK_PROGS([MARKDOWN], [markdown])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([mkfifo strerror])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
