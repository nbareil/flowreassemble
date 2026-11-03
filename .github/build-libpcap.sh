#!/bin/sh
# Builds a private, static libpcap for the Linux wheels (run inside the
# manylinux container, as root). Only the plain Linux capture backend is
# built, so the wheel depends on nothing but libc.
set -eu

VERSION=1.10.7
SHA256=68fa62cffb974f4275641ce14c2e2d75739251f30e00e6a0900903b247d76a03

dnf install -y -q flex bison
cd "$(mktemp -d)"
curl -sSfLO "https://www.tcpdump.org/release/libpcap-$VERSION.tar.xz"
echo "$SHA256  libpcap-$VERSION.tar.xz" | sha256sum -c -
tar xf "libpcap-$VERSION.tar.xz"
cd "libpcap-$VERSION"
# In /usr, so pkg-config finds it without extra environment.
CFLAGS="-O2 -fPIC" ./configure --prefix=/usr --libdir=/usr/lib64 \
    --disable-shared --disable-usb --disable-netmap --disable-bluetooth \
    --disable-dbus --disable-rdma --without-libnl --without-dpdk
make -j"$(nproc)"
make install
