#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

"$root/scripts/build-elfinator32.sh"
"$root/scripts/build-examples32.sh"
exec "$root/build/elfinator32" "$@"
