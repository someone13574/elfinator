#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

find src examples gen-builtins -type f \( -name '*.c' -o -name '*.h' \) -exec clang-format -i {} +
