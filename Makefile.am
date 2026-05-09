bin_PROGRAMS = radius_parser

radius_parser_SOURCES = \
    src/main.c \
    src/capture.c \
    src/parser.c \
    src/worker.c \
    src/user_session.c \
    src/modules/mysql/db.c \
    src/modules/cgnat/cgnat_handler.c \
    src/modules/cgnat/whitelist_handler.c

radius_parser_CPPFLAGS = -I$(top_srcdir)/include \
                         -I$(top_srcdir)/src/modules

radius_parser_LDADD = -lpcap -lpthread -lmysqlclient