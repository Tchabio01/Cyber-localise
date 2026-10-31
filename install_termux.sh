#!/data/data/com.termux/files/usr/bin/bash
set -e
pkg update -y
pkg install python unzip curl -y
termux-setup-storage || true
HERE="$(cd "$(dirname "$0")" && pwd)"
chmod +x "$HERE/start.sh"
python -m py_compile "$HERE/cyberwatch.py"
echo "Installation terminée. Lance : cd \"$HERE\" && ./start.sh"
echo "Puis ouvre http://127.0.0.1:8080 dans ton navigateur."
