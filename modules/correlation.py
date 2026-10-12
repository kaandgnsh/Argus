#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Correlation + Graph + Timeline."""

import time

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core import database as db


def run(seed):
    print(f"\n============= {Yeşil}CORRELATION{Bitir} =============")
    if not seed:
        print(f"{Kırmızı}[✗]{Bitir} Boş sorgu.")
        return
    seed = seed.strip()
    print(f"{Sarı}[*]{Bitir} Seed: {Beyaz}{seed}{Bitir}\n")

    # Entity eşleşmesi
    entities = db.get_entities(limit=500)
    matched_entities = [
        row for row in entities
        if row[1] == seed or seed in row[1]
    ]
    if matched_entities:
        print(f"{Sarı}[*]{Bitir} Eşleşen entity'ler:")
        for etype, value, data, source, conf, ts in matched_entities[:20]:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
            print(f"  [{Cyan}{etype:<14}{Bitir}] {Yeşil}{value}{Bitir}  "
                  f"{Mor}({source}, {conf}, {when}){Bitir}")

    # Relation eşleşmesi
    rels = db.get_relations(limit=1000)
    matched = [r for r in rels if r[0] == seed or r[1] == seed]
    if not matched and not matched_entities:
        print(f"{Mor}[i]{Bitir} Bu seed için kayıtlı ilişki yok.")
        print(f"{Mor}[i]{Bitir} Önce ilgili modülleri çalıştır (nickname, email, ip, domain...).")
        return

    if matched:
        print(f"\n{Sarı}[*]{Bitir} İlişki grafiği ({len(matched)} kenar):")
        for src, dst, kind, ev, ts in matched:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
            print(f"  {Yeşil}{src}{Bitir} --[{Cyan}{kind}{Bitir}]--> {Yeşil}{dst}{Bitir}"
                  f"  {Mor}({when}){Bitir}")
            if ev:
                print(f"      {Beyaz}evidence: {ev[:100]}{Bitir}")

        print(f"\n{Sarı}[*]{Bitir} Timeline:")
        for src, dst, kind, ev, ts in sorted(matched, key=lambda x: x[4]):
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
            print(f"  {Cyan}{when}{Bitir}  {src} -> {dst} ({kind})")


def link(src, dst, kind, evidence=""):
    db.add_relation(src, dst, kind, evidence)