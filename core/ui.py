#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

import os
import sys

from core.colors import (
    Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir, Kalın, AltıÇizili,
)
from core.banner import render as render_banner


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner(version):
    print(render_banner(version=version))


MENU = f"""
========== {Kırmızı}{AltıÇizili}ARGUS MENU{Bitir} ==========
{Kırmızı}[ 1]{Bitir} MEGA PHONE SEARCH
{Kırmızı}[ 2]{Bitir} DEEP NICK SEARCH
{Kırmızı}[ 3]{Bitir} EMAIL INTELLIGENCE
{Kırmızı}[ 4]{Bitir} DOMAIN INTELLIGENCE
{Kırmızı}[ 5]{Bitir} DNS INTELLIGENCE
{Kırmızı}[ 6]{Bitir} IP INTELLIGENCE
{Kırmızı}[ 7]{Bitir} URL INTELLIGENCE
{Kırmızı}[ 8]{Bitir} HASH LOOKUP
{Kırmızı}[ 9]{Bitir} GITHUB INTELLIGENCE
{Kırmızı}[10]{Bitir} THREAT INTEL
{Kırmızı}[11]{Bitir} FILE INTELLIGENCE
{Kırmızı}[12]{Bitir} DORK SCANNER
{Kırmızı}[13]{Bitir} CORRELATION
{Kırmızı}[14]{Bitir} CASES
{Kırmızı}[15]{Bitir} EXIF EXTRACTOR  (Görüntü Metadata)
{Kırmızı}[ 0]{Bitir} Hakkında
{Kırmızı}[99]{Bitir} Çıkış
"""


def print_menu():
    print(MENU)


def info(m): print(f"{Cyan}[i]{Bitir} {Beyaz}{m}{Bitir}")
def ok(m):   print(f"{Yeşil}[✓]{Bitir} {Beyaz}{m}{Bitir}")
def warn(m): print(f"{Sarı}[!]{Bitir} {Beyaz}{m}{Bitir}")
def err(m):  print(f"{Kırmızı}[✗]{Bitir} {Beyaz}{m}{Bitir}")


def about(version):
    print(f"""
{Kalın}{Kırmızı}ARGUS{Bitir} — Public OSINT & Recon Framework
{Sarı}Version :{Bitir} {version}
{Sarı}Purpose :{Bitir} Yetkili olduğun sistemler ve kamuya açık veriler üzerinde
          bilgi toplama. Özel hesaplara erişim, bypass, saldırı YOK.
{Sarı}License :{Bitir} MIT
""")


def pause(msg="Devam etmek için ENTER..."):
    try:
        input(f"\n{Mor}{msg}{Bitir}")
    except (EOFError, KeyboardInterrupt):
        sys.exit(0)


def ask(prompt, default=None):
    try:
        v = input(f"{Beyaz}{prompt}{Yeşil}").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return v or default