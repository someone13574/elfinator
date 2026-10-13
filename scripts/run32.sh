#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

"$root/scripts/build.sh"
exec "$root/build/elfinator32" "$@"
