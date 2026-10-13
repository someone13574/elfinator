#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p build
gcc -std=c11 -Wall -Wextra -g -DIMAGE_ARCH=IMAGE_ARCH_PE_PLUS -o build/elfinator src/*.c
gcc -m32 -std=c11 -Wall -Wextra -g -fno-pie -no-pie -DIMAGE_ARCH=IMAGE_ARCH_PE -o build/elfinator32 src/*.c

x86_64-w64-mingw32-dlltool -d examples/freestanding_loader.def -l build/libloader.a
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

i686-w64-mingw32-dlltool -d examples/freestanding_loader.def -l build/libloader32.a
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
