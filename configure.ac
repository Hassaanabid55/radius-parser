AC_INIT([radius-parser], [1.0])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

AC_PROG_CC

AC_CONFIG_HEADERS([config.h])

CFLAGS="$CFLAGS -D_GNU_SOURCE -Wall -Wextra -std=gnu11"

#
# libpcap
#
AC_SEARCH_LIBS([pcap_open_live], [pcap], [],
[
    AC_MSG_ERROR([libpcap not found])
])

#
# pthread
#
AC_CHECK_LIB([pthread], [pthread_create], [],
[
    AC_MSG_ERROR([pthread not found])
])

#
# mysql
#
AC_CHECK_LIB([mysqlclient], [mysql_init], [],
[
    AC_MSG_ERROR([mysqlclient not found])
])

#
# rabbitmq-c
#
AC_CHECK_LIB([rabbitmq], [amqp_new_connection], [],
[
    AC_MSG_ERROR([librabbitmq not found])
])

AC_CONFIG_FILES([
Makefile
])

AC_CHECK_HEADERS([arpa/inet.h stdlib.h string.h pthread.h amqp.h amqp_tcp_socket.h])
AC_CHECK_FUNCS([strtoul memset memcpy])

AC_OUTPUT