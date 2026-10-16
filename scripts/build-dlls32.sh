#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p build/dlls32
i686-w64-mingw32-dlltool -d builtins/common/elfinator32.def -l build/libelfinator32.a

for src in build/gen/dlls32/*.c; do
    name="$(basename "$src" .c)"
    i686-w64-mingw32-gcc \
        -shared -nostdlib -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -Os \
        -Wl,-e,0 -Wl,--dynamicbase -Wl,--enable-reloc-section \
        -o "build/dlls32/$name.dll" "$src" "build/gen/defs32/$name.def" \
        -Lbuild -lelfinator32
done
