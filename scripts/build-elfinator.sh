#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p build
gcc -std=c11 -Wall -Wextra -g -pthread -DIMAGE_ARCH=IMAGE_ARCH_EITHER -DELFINATOR_COMPAT -o build/elfinator src/*.c
