#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p build
gcc -std=c11 -Wall -Wextra -g -o build/elfinator src/*.c

x86_64-w64-mingw32-dlltool -d examples/freestanding_loader.def -l build/libloader.a
x86_64-w64-mingw32-gcc \
    -nostdlib -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -Os \
    -Wl,-e,pe_entry -Wl,--dynamicbase -Wl,--enable-reloc-section \
    -o build/freestanding.exe examples/freestanding.c \
    -Lbuild -lloader
