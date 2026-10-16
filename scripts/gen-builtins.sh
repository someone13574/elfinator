#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

scripts/build-gen-builtins.sh "$@"
rm -rf build/gen
exec build/gen-builtins builtins/loader.h
