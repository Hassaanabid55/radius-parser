#!/bin/bash

set -e

apt update

apt install -y \
    build-essential \
    gcc \
    make \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libpcap-dev \
    libmysqlclient-dev \
    librabbitmq-dev \
    uthash-dev 