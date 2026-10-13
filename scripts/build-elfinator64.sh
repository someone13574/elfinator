#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p build
gcc -std=c11 -Wall -Wextra -g -DIMAGE_ARCH=IMAGE_ARCH_PE_PLUS -o build/elfinator64 src/*.c
