#!/bin/bash
project_dir="$(cd "$(dirname "$0")" && pwd -P)" || exit 1
exec /bin/bash "$project_dir/bootstrap/start-posix.sh" "$@"
