#!/usr/bin/env bash
set -euo pipefail

scripts="$(dirname "$0")"

"$scripts/build-elfinator64.sh"
"$scripts/build-elfinator32.sh"
"$scripts/build-elfinator.sh"
"$scripts/build-examples64.sh"
"$scripts/build-examples32.sh"
