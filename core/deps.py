#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

import importlib
from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Bitir


REQUIRED = {"requests": "requests", "bs4": "beautifulsoup4"}
OPTIONAL = {
    "phonenumbers": "phonenumbers",
    "dns": "dnspython",
    "PIL": "Pillow",
    "pypdf": "pypdf",
}


def _missing(m):
    out = []
    for imp, pip in m.items():
        try:
            importlib.import_module(imp)
        except ImportError:
            out.append(pip)
    return out


def has(import_name):
    try:
        importlib.import_module(import_name)
        return True
    except ImportError:
        return False


def report():
    req = _missing(REQUIRED)
    opt = _missing(OPTIONAL)
    if req:
        print(f"{Kırmızı}[✗]{Bitir} Zorunlu paketler eksik: {', '.join(req)}")
        print(f"{Sarı}[i]{Bitir} pip install -r requirements.txt")
    else:
        print(f"{Yeşil}[✓]{Bitir} {Beyaz}Zorunlu paketler tamam.{Bitir}")
    if opt:
        print(f"{Sarı}[i]{Bitir} Opsiyonel: {', '.join(opt)}")
    return len(req) == 0