#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""External tool installer — Termux, Linux dağıtımları, macOS.

Desteklenen platformlar:
  - Termux (Android)
  - Debian / Ubuntu / Mint / Pop!_OS
  - Fedora / RHEL / CentOS / Rocky / Alma
  - Arch / Manjaro / EndeavourOS
  - openSUSE
  - Alpine
  - macOS (Homebrew)

KURAL: Otomatik kurulum yok. Her zaman:
  1. Ne kurulacağını göster
  2. Kullanıcıdan onay iste
  3. Seçilen paket yöneticisini çağır
"""

import os
import platform
import shutil
import subprocess

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir


TOOL_DB = {
    "exiftool": {
        "desc": "Görüntü metadata (EXIF/XMP/IPTC) — en kapsamlı backend",
        "packages": {
            "termux":   ["exiftool"],
            "debian":   ["libimage-exiftool-perl"],
            "ubuntu":   ["libimage-exiftool-perl"],
            "fedora":   ["perl-Image-ExifTool"],
            "arch":     ["perl-image-exiftool"],
            "opensuse": ["exiftool"],
            "alpine":   ["exiftool"],
            "macos":    ["exiftool"],
        },
    },
    "ffprobe": {
        "desc": "Medya metadata (audio/video codec, süre, bitrate)",
        "packages": {
            "termux":   ["ffmpeg"],
            "debian":   ["ffmpeg"],
            "ubuntu":   ["ffmpeg"],
            "fedora":   ["ffmpeg"],
            "arch":     ["ffmpeg"],
            "opensuse": ["ffmpeg"],
            "alpine":   ["ffmpeg"],
            "macos":    ["ffmpeg"],
        },
    },
    "nmap": {
        "desc": "Port taraması ve servis tespiti",
        "packages": {
            "termux":   ["nmap"],
            "debian":   ["nmap"],
            "ubuntu":   ["nmap"],
            "fedora":   ["nmap"],
            "arch":     ["nmap"],
            "opensuse": ["nmap"],
            "alpine":   ["nmap"],
            "macos":    ["nmap"],
        },
    },
    "amass": {
        "desc": "Subdomain enumeration (OWASP)",
        "packages": {
            "termux":   ["amass"],
            "debian":   ["amass"],
            "ubuntu":   ["amass"],
            "arch":     ["amass"],
            "macos":    ["amass"],
        },
    },
    "gobuster": {
        "desc": "Dizin/dosya brute force",
        "packages": {
            "termux":   ["gobuster"],
            "debian":   ["gobuster"],
            "ubuntu":   ["gobuster"],
            "arch":     ["gobuster"],
            "macos":    ["gobuster"],
        },
    },
    "whois": {
        "desc": "WHOIS sorgusu (RDAP tamamlayıcı)",
        "packages": {
            "termux":   ["whois"],
            "debian":   ["whois"],
            "ubuntu":   ["whois"],
            "fedora":   ["whois"],
            "arch":     ["whois"],
            "opensuse": ["whois"],
            "alpine":   ["whois"],
            "macos":    ["whois"],
        },
    },
}


def detect_platform():
    """Çalışılan platformu tespit eder."""
    # Termux kontrolü
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix or os.path.exists("/data/data/com.termux"):
        return "termux"

    system = platform.system().lower()

    if system == "darwin":
        return "macos"

    if system == "linux":
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                content = f.read().lower()
        except OSError:
            return "linux"

        # Sıra önemli — Ubuntu, Debian'a dahil olabilir
        if "ubuntu" in content or "mint" in content or "pop!_os" in content:
            return "ubuntu"
        if "debian" in content:
            return "debian"
        if any(x in content for x in ("fedora", "rhel", "centos", "rocky", "alma")):
            return "fedora"
        if "arch" in content or "manjaro" in content or "endeavour" in content:
            return "arch"
        if "opensuse" in content or "suse" in content:
            return "opensuse"
        if "alpine" in content:
            return "alpine"
        return "linux"

    return "unknown"


def _sudo_prefix():
    """Sudo gerekli mi? Termux'ta gerekmez, root isek de gerekmez."""
    if detect_platform() == "termux":
        return []
    if os.geteuid() == 0:
        return []
    if shutil.which("sudo"):
        return ["sudo"]
    if shutil.which("doas"):
        return ["doas"]
    return []


def get_install_cmd(tool):
    """Tool için kurulum komutunu (liste) döner. None: desteklenmiyor."""
    if tool not in TOOL_DB:
        return None

    plat = detect_platform()
    packages = TOOL_DB[tool]["packages"].get(plat)
    if not packages:
        return None

    sudo = _sudo_prefix()

    if plat == "termux":
        return ["pkg", "install", "-y"] + packages
    if plat in ("debian", "ubuntu"):
        return sudo + ["apt", "install", "-y"] + packages
    if plat == "fedora":
        return sudo + ["dnf", "install", "-y"] + packages
    if plat == "arch":
        return sudo + ["pacman", "-S", "--noconfirm"] + packages
    if plat == "opensuse":
        return sudo + ["zypper", "install", "-y"] + packages
    if plat == "alpine":
        return sudo + ["apk", "add"] + packages
    if plat == "macos":
        if not shutil.which("brew"):
            return None
        return ["brew", "install"] + packages
    return None


def is_installed(tool):
    return shutil.which(tool) is not None


def install(tool, confirm=True):
    """Tool'u kurar. Onay ister. Başarı bool döner."""
    if tool not in TOOL_DB:
        print(f"{Kırmızı}[✗]{Bitir} Bilinmeyen tool: {tool}")
        return False

    if is_installed(tool):
        print(f"{Yeşil}[✓]{Bitir} {tool} zaten kurulu.")
        return True

    plat = detect_platform()
    cmd = get_install_cmd(tool)

    print(f"\n{Sarı}[Kurulum]{Bitir} {Cyan}{tool}{Bitir}")
    print(f"  {Beyaz}Platform  :{Bitir} {Cyan}{plat}{Bitir}")
    print(f"  {Beyaz}Açıklama  :{Bitir} {TOOL_DB[tool]['desc']}")

    if cmd is None:
        print(f"\n{Kırmızı}[✗]{Bitir} Bu platformda otomatik kurulum "
              f"desteklenmiyor: {plat}")
        if tool == "exiftool":
            print(f"{Sarı}[i]{Bitir} Manuel: {Cyan}https://exiftool.org{Bitir}")
        elif tool == "ffprobe":
            print(f"{Sarı}[i]{Bitir} Manuel: {Cyan}https://ffmpeg.org{Bitir}")
        elif tool == "nmap":
            print(f"{Sarı}[i]{Bitir} Manuel: {Cyan}https://nmap.org{Bitir}")
        return False

    print(f"  {Beyaz}Komut     :{Bitir} {Cyan}{' '.join(cmd)}{Bitir}")

    if confirm:
        try:
            ans = input(f"\n{Sarı}Kurulsun mu? [y/N]:{Bitir} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if ans != "y":
            print(f"{Mor}[i]{Bitir} İptal edildi.")
            return False

    print(f"\n{Sarı}[*]{Bitir} Kurulum başlıyor...\n")
    try:
        result = subprocess.run(cmd, timeout=300)
    except subprocess.TimeoutExpired:
        print(f"\n{Kırmızı}[✗]{Bitir} Kurulum zaman aşımına uğradı (5 dk).")
        return False
    except (OSError, subprocess.SubprocessError) as e:
        print(f"\n{Kırmızı}[✗]{Bitir} Kurulum hatası: {e}")
        return False

    if result.returncode == 0 and is_installed(tool):
        print(f"\n{Yeşil}[✓]{Bitir} {tool} başarıyla kuruldu.")
        return True

    print(f"\n{Kırmızı}[✗]{Bitir} Kurulum başarısız "
          f"(çıkış kodu: {result.returncode})")
    return False


def ensure(tool, interactive=True):
    """Kurulu mu? Değilse kurulum teklif et. Kurulu mu döner."""
    if is_installed(tool):
        return True
    if not interactive:
        return False
    return install(tool, confirm=True)


def list_tools():
    """Kurulu/kurulu olmayan tüm araçları listeler."""
    plat = detect_platform()
    print(f"\n{Sarı}[*]{Bitir} Harici araçlar "
          f"(platform: {Cyan}{plat}{Bitir})\n")
    print(f"  {Beyaz}{'Tool':<14}{'Durum':<10}{'Açıklama'}{Bitir}")
    print(f"  {Mor}{'-' * 14}{'-' * 10}{'-' * 46}{Bitir}")

    for name, info in TOOL_DB.items():
        installed = is_installed(name)
        if installed:
            status = f"{Yeşil}KURULU{Bitir}"
            pad = " " * 4
        else:
            status = f"{Sarı}YOK{Bitir}"
            pad = " " * 7
        print(f"  {Cyan}{name:<14}{Bitir}{status}{pad} {info['desc']}")

    print(f"\n{Mor}[i]{Bitir} Kurmak için: "
          f"{Cyan}python3 argus.py --install-tools exiftool{Bitir}")
    print(f"{Mor}[i]{Bitir} Hepsini kurmak için: "
          f"{Cyan}python3 argus.py --install-tools all{Bitir}")