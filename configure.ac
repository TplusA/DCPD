AC_PREREQ([2.69])
AC_INIT([DCPD], [0.1], [r.tiemann@ta-hifi.com])
AM_INIT_AUTOMAKE([1.11 -Wall -Werror foreign])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([dcpd.c])
AC_CONFIG_HEADERS([config.h])

AC_USE_SYSTEM_EXTENSIONS()

# Checks for programs.
AC_PROG_CC
PKG_PROG_PKG_CONFIG([0.26])
AC_CHECK_PROGS([MARKDOWN], [markdown])
AC_CHECK_PROGS([DOXYGEN], [doxygen])

# Checks for libraries.
PKG_CHECK_MODULES([DCPD_DEPENDENCIES], [gmodule-2.0 gio-2.0 gio-unix-2.0 gthread-2.0])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stddef.h stdint.h stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getpagesize memchr memmove memset mkfifo strerror strtoul])

AC_CONFIG_FILES([Makefile Doxyfile])
AC_OUTPUT
