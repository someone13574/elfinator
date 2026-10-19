#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

scripts/gen-builtins.sh
scripts/build-dlls32.sh

mkdir -p build
gcc -std=c11 -Wall -Wextra -g -pthread -DIMAGE_ARCH=IMAGE_ARCH_EITHER -DELFINATOR_COMPAT \
    -Isrc -Ibuiltins -o build/elfinator src/*.c src/compat.S common/*.c builtins/*.c \
    build/gen/builtin_dlls.c
