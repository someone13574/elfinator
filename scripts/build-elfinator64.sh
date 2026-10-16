#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

scripts/gen-builtins.sh

mkdir -p build
gcc -std=c11 -Wall -Wextra -g -DIMAGE_ARCH=IMAGE_ARCH_PE_PLUS -Isrc -Ibuiltins \
    -o build/elfinator64 src/*.c builtins/*.c build/gen/builtin_dlls.c
