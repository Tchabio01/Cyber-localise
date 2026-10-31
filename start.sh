#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$(dirname "$0")"
export PYTHONUNBUFFERED=1
python cyberwatch.py
