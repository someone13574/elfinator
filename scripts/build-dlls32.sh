#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p build
i686-w64-mingw32-gcc \
    -shared -nostdlib -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -Os \
    -Wl,-e,_DllMain@12 -Wl,--dynamicbase -Wl,--enable-reloc-section \
    -Wl,--out-implib,build/libloader32.a \
    -o build/loader32.dll dlls/loader.c examples/freestanding_loader.def
