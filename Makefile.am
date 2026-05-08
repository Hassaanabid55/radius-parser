bin_PROGRAMS = radius_parser

radius_parser_SOURCES = \
    src/main.c \
    src/capture.c \
    src/parser.c \
    src/worker.c \
    src/user_session.c

radius_parser_CPPFLAGS = -I$(top_srcdir)/include

radius_parser_LDADD = -lpcap -lpthread