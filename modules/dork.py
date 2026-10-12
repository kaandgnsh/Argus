#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from modules import search as search_provider


DEFAULT_TEMPLATES = [
    '"{t}"',
    'site:pastebin.com "{t}"',
    'site:github.com "{t}"',
    '"{t}" filetype:pdf',
    '"{t}" filetype:docx',
    '"{t}" filetype:xlsx',
]


def generate(target, extra=None):
    tpl = list(DEFAULT_TEMPLATES)
    if extra:
        tpl.extend(extra)
    return [t.format(t=target) for t in tpl]


def run(target):
    print(f"\n============= {Yeşil}DORK SCANNER{Bitir} =============")
    if not target:
        print(f"{Kırmızı}[✗]{Bitir} Boş hedef.")
        return
    hits = 0
    for q in generate(target):
        print(f"\n{Sarı}[*]{Bitir} Dork: {Beyaz}{q}{Bitir}")
        results = search_provider.search(q, max_results=5)
        if not results:
            print(f"  {Mor}[i]{Bitir} Sonuç yok / provider limitli.")
            continue
        for url in results:
            print(f"  {Beyaz}[ {Yeşil}FOUND {Beyaz}]{Bitir} {Cyan}{url}{Bitir}")
            hits += 1
    print(f"\n{Sarı}[Özet]{Bitir} Toplam: {Yeşil}{hits}{Bitir}")