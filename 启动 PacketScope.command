#!/bin/zsh
set -eu
cd "${0:A:h}"
if [[ ! -x .venv/bin/python ]]; then
  for py in python3.13 python3.12 python3.11 python3.10 python3 "$HOME/miniconda3/bin/python3"; do
    if "$py" -c 'import sys; sys.exit(sys.version_info < (3,10))' 2>/dev/null; then
      "$py" -m venv .venv
      break
    fi
  done
fi
if [[ ! -x .venv/bin/python ]]; then
  print '请先安装 Python 3.10–3.13，然后重新打开。'
  read -k 1
  exit 1
fi
if ! .venv/bin/python -c 'from PySide6 import QtWidgets' 2>/dev/null; then
  .venv/bin/python -m pip install -r requirements.txt
fi
exec .venv/bin/python -m packetscope "$@"
