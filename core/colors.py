#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

# ===== COLORS (ORIGINAL - PROTECTED) =====
Mor = '\033[95m'
Cyan = '\033[96m'
KoyuMavi = '\033[36m'
Mavi = '\033[94m'
Yeşil = '\033[92m'
Sarı = '\033[93m'
Kırmızı = '\033[91m'
Kalın = '\033[1m'
AltıÇizili = '\033[4m'
Bitir = '\033[0m'
Beyaz = '\033[1;37m'


def disable():
    """Tüm renkleri kapatır (--no-color)."""
    global Mor, Cyan, KoyuMavi, Mavi, Yeşil, Sarı, Kırmızı, Kalın, AltıÇizili, Bitir, Beyaz
    Mor = Cyan = KoyuMavi = Mavi = Yeşil = Sarı = Kırmızı = ""
    Kalın = AltıÇizili = Bitir = Beyaz = ""