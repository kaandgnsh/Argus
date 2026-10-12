#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Bitir
from core import database as db
from core import ui


def run():
    while True:
        print(f"""
============= {Yeşil}CASES{Bitir} =============
{Kırmızı}[1]{Bitir} Yeni case oluştur
{Kırmızı}[2]{Bitir} Case listesi
{Kırmızı}[3]{Bitir} Entity listesi
{Kırmızı}[4]{Bitir} İlişki listesi
{Kırmızı}[0]{Bitir} Geri
""")
        c = ui.ask("Seçim: ")
        if c == "1":
            name = ui.ask("Case adı: ")
            note = ui.ask("Not (boş geçilebilir): ", default="")
            if name and db.create_case(name, note):
                ui.ok(f"Case oluşturuldu: {name}")
            else:
                ui.err("Case zaten var veya hata.")
        elif c == "2":
            rows = db.list_cases()
            if not rows:
                ui.info("Case yok.")
            for name, note, ts in rows:
                print(f"  {Yeşil}{name}{Bitir}  {Mor}{note}{Bitir}")
        elif c == "3":
            for row in db.get_entities(limit=50):
                etype, value, data, source, conf, ts = row
                print(f"  [{Cyan}{etype}{Bitir}] {value}  "
                      f"{Mor}({source}, {conf}){Bitir}")
        elif c == "4":
            for src, dst, kind, ev, ts in db.get_relations(limit=50):
                print(f"  {src} --[{kind}]--> {dst}")
        elif c == "0":
            return