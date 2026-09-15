#!/bin/sh
set -eu

if [ -n "${SG_PYTHON:-}" ]; then
  PYTHON=$SG_PYTHON
elif [ -x .venv/bin/python ]; then
  PYTHON=.venv/bin/python
else
  PYTHON=python3
fi

exec "$PYTHON" -m pytest "$@"
