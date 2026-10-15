#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

scripts/build-dlls32.sh

mkdir -p build
i686-w64-mingw32-gcc \
    -nostdlib -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -Os \
    -Wl,-e,_pe_entry -Wl,--dynamicbase -Wl,--enable-reloc-section \
    -o build/freestanding32.exe examples/freestanding.c \
    -Lbuild -lloader32

i686-w64-mingw32-gcc \
    -shared -nostdlib -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -Os \
    -Wl,-e,_DllMain@12 -Wl,--dynamicbase -Wl,--enable-reloc-section \
    -Wl,--out-implib,build/libwith_dll_lib32.a \
    -o build/with_dll_lib32.dll examples/with_dll_lib.c \
    -Lbuild -lloader32
i686-w64-mingw32-gcc \
    -nostdlib -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -Os \
    -Wl,-e,_pe_entry -Wl,--dynamicbase -Wl,--enable-reloc-section \
    -o build/with_dll32.exe examples/with_dll.c \
    -Lbuild -lwith_dll_lib32
