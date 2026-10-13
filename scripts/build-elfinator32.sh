#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p build
gcc -m32 -std=c11 -Wall -Wextra -g -fno-pie -no-pie -DIMAGE_ARCH=IMAGE_ARCH_PE -o build/elfinator32 src/*.c
