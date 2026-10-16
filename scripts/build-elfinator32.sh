#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

scripts/gen-builtins.sh

mkdir -p build
gcc -m32 -std=c11 -Wall -Wextra -g -fno-pie -no-pie -DIMAGE_ARCH=IMAGE_ARCH_PE \
    -Isrc -Ibuiltins -o build/elfinator32 src/*.c builtins/*.c \
    build/gen/builtin_dlls.c
