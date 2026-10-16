#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${LLVM_PREFIX:-}" ]]; then
    clang_path="$(command -v clang)" || { echo "error: clang not found, set LLVM_PREFIX" >&2; exit 1; }
    LLVM_PREFIX="$(dirname "$(dirname "$(readlink -f "$clang_path")")")"
fi

mkdir -p build
gcc -std=c11 -Wall -Wextra -g \
    -isystem "$LLVM_PREFIX/include" \
    -o build/gen-builtins gen-builtins/*.c \
    -L"$LLVM_PREFIX/lib" -Wl,-rpath,"$LLVM_PREFIX/lib" -lclang
