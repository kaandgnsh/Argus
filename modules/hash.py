#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Hash analiz — tip tespiti ve yerel hash hesabı."""

import hashlib
import re

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir


PATTERNS = [
    ("MD5",    re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("SHA1",   re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("SHA256", re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("SHA512", re.compile(r"^[a-f0-9]{128}$", re.I)),
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")),
]


def detect(h):
    for name, pat in PATTERNS:
        if pat.match(h.strip()):
            return name
    return None


def run(value):
    print(f"\n============= {Yeşil}HASH TOOL{Bitir} =============")
    if not value:
        print(f"{Kırmızı}[✗]{Bitir} Boş değer.")
        return
    t = detect(value)
    if t:
        print(f"{Sarı}[*]{Bitir} Algılanan tip: {Yeşil}{t}{Bitir}")
    else:
        print(f"{Mor}[i]{Bitir} Bilinen hash formatı değil. Yerel hash üretiliyor...")

    raw = value.encode("utf-8")
    print(f"  {Beyaz}MD5    :{Bitir} {Cyan}{hashlib.md5(raw).hexdigest()}{Bitir}")
    print(f"  {Beyaz}SHA1   :{Bitir} {Cyan}{hashlib.sha1(raw).hexdigest()}{Bitir}")
    print(f"  {Beyaz}SHA256 :{Bitir} {Cyan}{hashlib.sha256(raw).hexdigest()}{Bitir}")
    print(f"  {Beyaz}SHA512 :{Bitir} {Cyan}{hashlib.sha512(raw).hexdigest()}{Bitir}")