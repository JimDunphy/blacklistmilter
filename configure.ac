# Process this file with autoconf to produce a configure script.

AC_INIT(blackmilter.c)

AC_PROG_CC
AC_PROG_INSTALL

CFLAGS="${CFLAGS} -ansi -pedantic -U__STRICT_ANSI__ -Wall -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wno-long-long"
CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
LDFLAGS="${LDFLAGS} -L/usr/local/lib"

AC_HEADER_STDC
AC_CHECK_HEADERS([sys/socket.h netinet/in.h arpa/inet.h sys/un.h])

AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_SIZE_T

AC_CHECK_FUNCS([daemon setsid])

# Check for pthread library.  On some systems it's in libc_r and must
# be invoked via the special -pthread flag; on other systems it's just
# a regular -lpthread library.
AC_CHECK_LIB([c_r],[pthread_create],[LIBS="-pthread $LIBS"],[AC_CHECK_LIB([pthread],[pthread_create])])

# Check for the milter library.  Libmilter uses pthreads, so we have to do this
# check after the pthread one and use the library list it gave us.
AC_CHECK_LIB([milter],[smfi_main],,,$LIBS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
