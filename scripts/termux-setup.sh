#!/data/data/com.termux/files/usr/bin/sh
# SiteIntel one-shot setup for Termux (Realme C30 friendly: no root, no Docker).
set -e

pkg update -y
pkg install -y python -y

# All required deps are pure Python and install cleanly with pip:
pip install --upgrade pip
pip install -r requirements.txt

# OPTIONAL: faster/nicer parsing of INVALID certificates (valid ones work without it):
#   pkg install -y python-cryptography

# OPTIONAL: run the test suite:
#   pip install pytest && python -m pytest -q

echo "Done. Try:  python main.py example.com"
