#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""ARGUS — Public OSINT & Recon Framework.

Entry point. Hem interaktif menü hem CLI destekler.
"""

import json
import sys

from core.config import CONFIG
from core import deps as deps_check
from core import ui
from core.cli import parse
from core.colors import disable as disable_colors


def _dump_json(data):
    print(json.dumps(data, indent=2, default=str, ensure_ascii=False))


def _export_all(args):
    from core import reports

    payload = reports.collect_scan_data()
    generated = []

    if args.export_json or args.export_all:
        path = reports.export_json(payload)
        generated.append(("JSON", path))

    if args.export_html or args.export_all:
        path = reports.export_html(payload, title="ARGUS Scan Report")
        generated.append(("HTML", path))

    if args.export_csv or args.export_all:
        paths = reports.export_csv(payload)
        for p in paths:
            generated.append(("CSV", p))

    if args.export_md or args.export_all:
        path = reports.export_markdown(payload)
        generated.append(("Markdown", path))

    if args.export_dot or args.export_all:
        path = reports.export_dot()
        generated.append(("DOT", path))

    if generated:
        print()
        for label, path in generated:
            ui.ok(f"{label:<10} {path}")


def _interactive():
    version = CONFIG["app"]["version"]
    while True:
        ui.clear()
        ui.print_banner(version)
        ui.print_menu()
        choice = ui.ask("Seçim: ")
        if choice is None:
            sys.exit(0)
        try:
            if choice == "1":
                from modules import phone
                phone.run(ui.ask("Hedef Numara: "))
            elif choice == "2":
                from modules import nickname
                nickname.run(ui.ask("Hedef Nick: "))
            elif choice == "3":
                from modules import email as email_mod
                email_mod.run(ui.ask("Hedef Email: "))
            elif choice == "4":
                from modules import domain
                domain.run(ui.ask("Hedef Domain: "))
            elif choice == "5":
                from modules import domain
                domain.run(ui.ask("Hedef Domain: "))
            elif choice == "6":
                from modules import ip as ip_mod
                ip_mod.run(ui.ask("Hedef IP: "))
            elif choice == "7":
                from modules import url as url_mod
                url_mod.run(ui.ask("Hedef URL: "))
            elif choice == "8":
                from modules import hash as hash_mod
                hash_mod.run(ui.ask("Hash veya değer: "))
            elif choice == "9":
                from modules import github
                github.run(ui.ask("GitHub kullanıcı: "))
            elif choice == "10":
                from modules import threat
                threat.run(ui.ask("IOC (IP/domain/URL/hash/CVE): "))
            elif choice == "11":
                from modules import file_intel
                file_intel.run(ui.ask("Dosya yolu: "))
            elif choice == "12":
                from modules import dork
                dork.run(ui.ask("Hedef Bilgi: "))
            elif choice == "13":
                from modules import correlation
                correlation.run(ui.ask("Seed (entity): "))
            elif choice == "14":
                from modules import cases
                cases.run()
            elif choice == "15":
                from modules import exif
                path = ui.ask("Görüntü dosyası: ")
                save_thumb = (ui.ask("Gömülü thumbnail'i kaydet? [y/N]: ",
                                     default="n") or "n").lower() == "y"
                exif.run(path, save_thumb=save_thumb)
            elif choice == "0":
                ui.about(version)
                ui.pause()
            elif choice == "99":
                print(f"\n{ui.Mor}Görüşürüz.{ui.Bitir}\n")
                sys.exit(0)
            else:
                ui.warn("Geçersiz seçim.")
        except KeyboardInterrupt:
            print()
        except Exception as e:
            ui.err(f"Hata: {e}")
        ui.pause()


def _cli(args):
    if args.no_color:
        disable_colors()
        import core.ui as ui_mod
        ui_mod.Kırmızı = ui_mod.Yeşil = ui_mod.Sarı = ui_mod.Beyaz = ""
        ui_mod.Mor = ui_mod.Cyan = ui_mod.Kalın = ui_mod.AltıÇizili = ui_mod.Bitir = ""

    if args.clear_cache:
        from core.cache import clear
        clear()
        ui.ok("Cache temizlendi.")
        return

    only_export = any([args.export_json, args.export_html, args.export_csv,
                       args.export_md, args.export_dot, args.export_all])
    has_target = any([
        args.phone, args.username, args.email, args.domain, args.dns,
        args.ip, args.url, args.hash_value, args.dork, args.search,
        args.github, args.threat, args.file_path, args.correlate,
        args.exif_path,
    ])
    if only_export and not has_target:
        _export_all(args)
        return

    handled = False
    if args.phone:
        from modules import phone
        phone.run(args.phone); handled = True
    if args.username:
        from modules import nickname
        nickname.run(args.username); handled = True
    if args.email:
        from modules import email as email_mod
        email_mod.run(args.email); handled = True
    if args.domain:
        from modules import domain
        domain.run(args.domain, subdomain_log=args.subdomain_log); handled = True
    if args.dns:
        from modules import domain
        domain.run(args.dns, subdomain_log=args.subdomain_log); handled = True
    if args.ip:
        from modules import ip as ip_mod
        ip_mod.run(args.ip, show_world_map=not args.no_map); handled = True
    if args.url:
        from modules import url as url_mod
        url_mod.run(args.url); handled = True
    if args.hash_value:
        from modules import hash as hash_mod
        hash_mod.run(args.hash_value); handled = True
    if args.dork:
        from modules import dork
        dork.run(args.dork); handled = True
    if args.github:
        from modules import github
        github.run(args.github); handled = True
    if args.threat:
        from modules import threat
        threat.run(args.threat); handled = True
    if args.file_path:
        from modules import file_intel
        file_intel.run(args.file_path); handled = True
    if args.exif_path:
        from modules import exif
        exif.run(args.exif_path, save_thumb=args.save_thumb,
                 json_output=args.json); handled = True
    if args.correlate:
        from modules import correlation
        correlation.run(args.correlate); handled = True
    if args.search:
        from modules import search as sp
        results = sp.search(args.search,
                            max_results=CONFIG["search"]["max_results"])
        if args.json:
            _dump_json(results)
        else:
            for u in results:
                print(u)
            if not results:
                ui.warn("Sonuç yok / provider limitli.")
        handled = True

    if not handled:
        _interactive()
        return

    if (args.export_json or args.export_html or args.export_csv
            or args.export_md or args.export_dot or args.export_all):
        _export_all(args)


def main():
    args = parse(version=CONFIG["app"]["version"])
    if not deps_check.report():
        sys.exit(2)
    _cli(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(130)