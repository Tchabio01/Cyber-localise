#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$(dirname "$0")"
export PYTHONUNBUFFERED=1
if [ -f ".env" ]; then
  set -a
  . ./.env
  set +a
fi
python cyberwatch.py
