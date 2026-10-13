#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

"$root/scripts/build-elfinator64.sh"
"$root/scripts/build-examples64.sh"
exec "$root/build/elfinator64" "$@"
