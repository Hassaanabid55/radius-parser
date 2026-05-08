#!/bin/bash
set -e

autoreconf -fi
./configure
make -j$(nproc)

mkdir -p bin
cp radius_parser bin/

echo "Build complete → bin/radius_parser"