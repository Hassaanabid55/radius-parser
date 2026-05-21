#!/bin/bash

set -e

make clean || true

rm -rf \
    autom4te.cache \
    aclocal.m4 \
    compile \
    config.guess \
    config.sub \
    configure \
    depcomp \
    install-sh \
    missing \
    Makefile.in \
    config.h.in \
    config.h \
    config.log \
    config.status \
    stamp-h1 \
    .deps \
    src/.deps \
    src/.dirstamp \
    src/modules/cgnat/.deps \
    src/modules/cgnat/.dirstamp \
    src/modules/mysql/.deps \
    src/modules/mysql/.dirstamp \
    src/modules/rabbitmq/.deps \
    src/modules/rabbitmq/.dirstamp \
    bin/radius_parser

find . -name "*.o" -delete
find . -name "*.Po" -delete
find . -name "*.lo" -delete

echo "Project cleaned"