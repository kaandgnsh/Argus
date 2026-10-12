#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

import argparse


def build_parser(version):
    p = argparse.ArgumentParser(
        prog="argus",
        description="ARGUS — Public OSINT & Recon Framework",
    )
    p.add_argument("--version", action="version", version=f"ARGUS {version}")

    g = p.add_argument_group("Hedef tipleri")
    g.add_argument("-phone", metavar="NUMBER")
    g.add_argument("-username", "-u", metavar="USER")
    g.add_argument("-email", metavar="EMAIL")
    g.add_argument("-domain", metavar="DOMAIN")
    g.add_argument("-dns", metavar="DOMAIN")
    g.add_argument("-ip", metavar="IP")
    g.add_argument("-url", metavar="URL")
    g.add_argument("-hash", dest="hash_value", metavar="HASH")
    g.add_argument("-dork", metavar="QUERY")
    g.add_argument("-search", metavar="QUERY")
    g.add_argument("-github", metavar="USER")
    g.add_argument("-threat", metavar="IOC")
    g.add_argument("-file", dest="file_path", metavar="PATH")
    g.add_argument("-exif", dest="exif_path", metavar="IMAGE",
                   help="Görüntü dosyasından tüm EXIF metadata'yı çıkar")
    g.add_argument("-correlate", metavar="QUERY")

    e = p.add_argument_group("Export")
    e.add_argument("--export-json", action="store_true",
                   help="Sonuçları JSON olarak kaydet")
    e.add_argument("--export-html", action="store_true",
                   help="Modern HTML raporu kaydet")
    e.add_argument("--export-csv", action="store_true",
                   help="entities.csv + relations.csv kaydet")
    e.add_argument("--export-md", action="store_true",
                   help="Markdown raporu kaydet (GitHub uyumlu)")
    e.add_argument("--export-dot", action="store_true",
                   help="GraphViz DOT grafiği kaydet")
    e.add_argument("--export-all", action="store_true",
                   help="JSON + HTML + CSV + MD + DOT hepsini üret")

    t = p.add_argument_group("Harici araç yönetimi")
    t.add_argument("--install-tools", metavar="TOOL", nargs="?", const="all",
                   help="Harici bir aracı kur (exiftool/ffprobe/nmap/...) "
                        "veya 'all' ile hepsini listele")
    t.add_argument("--list-tools", action="store_true",
                   help="Kurulu ve eksik harici araçları listele")

    o = p.add_argument_group("Çıktı seçenekleri")
    o.add_argument("--subdomain-log", metavar="PATH",
                   help="Domain taramasında subdomain tam listesini bu "
                        "dosyaya yaz")
    o.add_argument("--no-map", action="store_true",
                   help="IP sorgusunda ASCII dünya haritasını gösterme")
    o.add_argument("--save-thumb", action="store_true",
                   help="EXIF'ten gömülü thumbnail'i reports/ altına kaydet")

    p.add_argument("--json", action="store_true", help="JSON stdout çıktısı")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--clear-cache", action="store_true")
    return p


def parse(argv=None, version="0.1.0"):
    return build_parser(version).parse_args(argv)