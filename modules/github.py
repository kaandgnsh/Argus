#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from providers import registry


def run(username):
    print(f"\n============= {Yeşil}GITHUB INTELLIGENCE{Bitir} =============")
    if not username:
        print(f"{Kırmızı}[✗]{Bitir} Boş kullanıcı.")
        return
    p = registry.get("github_api")
    if p is None or not getattr(p, "enabled", True):
        print(f"{Mor}[!]{Bitir} github_api provider kapalı.")
        return
    print(f"{Sarı}[*]{Bitir} Hedef: {Beyaz}{username}{Bitir}\n")
    try:
        u = p.query(username)
    except Exception as e:
        print(f"{Kırmızı}[✗]{Bitir} {e}")
        return
    if not u:
        print(f"{Kırmızı}[✗]{Bitir} Kullanıcı bulunamadı.")
        return
    for k in ("login", "name", "company", "blog", "location",
              "email", "bio", "public_repos", "followers", "following",
              "created_at", "updated_at"):
        v = u.get(k)
        if v:
            print(f"  {Beyaz}{k:<14}:{Bitir} {Yeşil}{v}{Bitir}")
    print(f"  {Beyaz}profile       :{Bitir} {Cyan}{u.get('html_url','')}{Bitir}")

    print(f"\n{Sarı}[*]{Bitir} Public repos...")
    try:
        repos = p.repos(username, limit=15)
        for r in repos[:15]:
            print(f"  {Yeşil}{r.get('name'):<30}{Bitir} "
                  f"{Cyan}{r.get('html_url','')}{Bitir}")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} {e}")