#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p build
x86_64-w64-mingw32-dlltool -d build/gen/defs64/loader.def -l build/libloader.a
x86_64-w64-mingw32-gcc \
    -nostdlib -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -Os \
    -Wl,-e,pe_entry -Wl,--dynamicbase -Wl,--enable-reloc-section \
    -o build/freestanding.exe examples/freestanding.c \
    -Lbuild -lloader

x86_64-w64-mingw32-gcc \
    -shared -nostdlib -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -Os \
    -Wl,-e,DllMain -Wl,--dynamicbase -Wl,--enable-reloc-section \
    -Wl,--out-implib,build/libwith_dll_lib.a \
    -o build/with_dll_lib.dll examples/with_dll_lib.c \
    -Lbuild -lloader
x86_64-w64-mingw32-gcc \
    -nostdlib -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -Os \
    -Wl,-e,pe_entry -Wl,--dynamicbase -Wl,--enable-reloc-section \
    -o build/with_dll.exe examples/with_dll.c \
    -Lbuild -lwith_dll_lib
