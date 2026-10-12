#!/bin/sh
# KaanDGN ARGUS — installer
# Ne yaptığını açıkça gösterir. Otomatik dev download YAPMAZ.

set -e

echo "[ARGUS] Zorunlu paketler kuruluyor (pip install -r requirements.txt)"
pip install -r requirements.txt

echo
echo "[ARGUS] Opsiyonel paketler (Pillow, pypdf) — isteğe bağlı."
printf "  Kurulsun mu? [y/N]: "
read ans
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
    pip install -r requirements-optional.txt
else
    echo "[ARGUS] Opsiyonel paketler atlandı."
fi

echo
echo "[ARGUS] Kurulum tamam. Çalıştır: python3 argus.py"