#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Universal File Intelligence — metadata, hash, IOC.

Dosya çalıştırılmaz. Subprocess shell=False.
"""

import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core.deps import has
from core.security import archive_is_suspicious, is_safe_path


URL_RE = re.compile(r"https?://[^\s\"'<>()]+", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _magic_type(path):
    if has("magic"):
        try:
            import magic
            return magic.from_file(path, mime=True)
        except Exception:
            pass
    ext = Path(path).suffix.lower().lstrip(".")
    return f"application/x-{ext}" if ext else "application/octet-stream"


def _hashes(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1 << 16)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                sha512.update(chunk)
    except OSError:
        pass
    return {
        "md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(), "sha512": sha512.hexdigest(),
    }


def _extract_iocs(blob):
    try:
        text = blob.decode("utf-8", errors="ignore")
    except Exception:
        return {"urls": [], "emails": [], "ips": []}
    return {
        "urls": sorted(set(URL_RE.findall(text)))[:20],
        "emails": sorted(set(EMAIL_RE.findall(text)))[:20],
        "ips": sorted(set(IP_RE.findall(text)))[:20],
    }


def _image(path):
    if not has("PIL"):
        print(f"  {Mor}[i]{Bitir} Pillow yok — resim metadata atlandı.")
        return
    from PIL import Image, ExifTags
    try:
        with Image.open(path) as im:
            print(f"  {Beyaz}Format     :{Bitir} {Yeşil}{im.format} {im.size} {im.mode}{Bitir}")
            exif = im.getexif() or {}
            for tag_id, val in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                print(f"  {Beyaz}{str(tag):<12}:{Bitir} {Yeşil}{val}{Bitir}")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} Resim analiz hatası: {e}")


def _pdf(path):
    if not has("pypdf"):
        print(f"  {Mor}[i]{Bitir} pypdf yok — PDF metadata atlandı.")
        return
    from pypdf import PdfReader
    try:
        r = PdfReader(path)
        meta = r.metadata or {}
        for k in ("/Author", "/Creator", "/Producer", "/Title", "/Subject",
                  "/CreationDate", "/ModDate"):
            v = meta.get(k)
            if v:
                print(f"  {Beyaz}{k:<14}:{Bitir} {Yeşil}{v}{Bitir}")
        print(f"  {Beyaz}Pages        :{Bitir} {Yeşil}{len(r.pages)}{Bitir}")
        txt = ""
        for p in r.pages[:5]:
            try:
                txt += p.extract_text() or ""
            except Exception:
                pass
        iocs = _extract_iocs(txt.encode("utf-8"))
        for k, v in iocs.items():
            if v:
                print(f"  {Beyaz}{k:<14}:{Bitir} {Cyan}{'; '.join(v[:5])}{Bitir}")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} PDF hatası: {e}")


def _ffprobe(path):
    if not shutil.which("ffprobe"):
        return None
    try:
        res = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json",
             "-show_format", "-show_streams", path],
            capture_output=True, text=True, timeout=20,
        )
        if res.returncode == 0:
            import json
            return json.loads(res.stdout)
    except (subprocess.SubprocessError, OSError, ValueError):
        return None
    return None


def _media(path):
    j = _ffprobe(path)
    if not j:
        print(f"  {Mor}[i]{Bitir} ffprobe yok — medya metadata kısıtlı.")
        return
    fmt = j.get("format", {})
    for k in ("format_name", "duration", "bit_rate", "size"):
        v = fmt.get(k)
        if v:
            print(f"  {Beyaz}{k:<14}:{Bitir} {Yeşil}{v}{Bitir}")
    for s in j.get("streams", [])[:5]:
        print(f"  {Beyaz}stream      :{Bitir} {Yeşil}{s.get('codec_type')} "
              f"{s.get('codec_name')} {s.get('width','')}x{s.get('height','')}{Bitir}")


def _zip(path):
    try:
        with zipfile.ZipFile(path) as z:
            members = [(i.filename, i.file_size) for i in z.infolist()]
            bad, reason = archive_is_suspicious(members, os.path.getsize(path))
            if bad:
                print(f"  {Kırmızı}[!]{Bitir} Şüpheli arşiv: {reason}")
                return
            print(f"  {Beyaz}Entries     :{Bitir} {Yeşil}{len(members)}{Bitir}")
            for name, size in members[:20]:
                print(f"  {Cyan}{name} ({size} B){Bitir}")
    except zipfile.BadZipFile as e:
        print(f"  {Mor}[!]{Bitir} Zip hatası: {e}")


def _tar(path):
    try:
        with tarfile.open(path) as t:
            members = [(m.name, m.size) for m in t.getmembers()]
            bad, reason = archive_is_suspicious(members, os.path.getsize(path))
            if bad:
                print(f"  {Kırmızı}[!]{Bitir} Şüpheli arşiv: {reason}")
                return
            print(f"  {Beyaz}Entries     :{Bitir} {Yeşil}{len(members)}{Bitir}")
            for name, size in members[:20]:
                print(f"  {Cyan}{name} ({size} B){Bitir}")
    except tarfile.TarError as e:
        print(f"  {Mor}[!]{Bitir} Tar hatası: {e}")


def run(path):
    print(f"\n============= {Yeşil}FILE INTELLIGENCE{Bitir} =============")
    if not path or not os.path.exists(path):
        print(f"{Kırmızı}[✗]{Bitir} Dosya yok: {path}")
        return
    if not is_safe_path(path):
        print(f"{Kırmızı}[✗]{Bitir} Güvensiz yol.")
        return

    p = Path(path)
    st = p.stat()
    print(f"{Sarı}[*]{Bitir} Dosya: {Beyaz}{p}{Bitir}\n")
    print(f"  {Beyaz}Ad          :{Bitir} {Yeşil}{p.name}{Bitir}")
    print(f"  {Beyaz}Uzantı      :{Bitir} {Yeşil}{p.suffix or '-'}{Bitir}")
    print(f"  {Beyaz}Boyut       :{Bitir} {Yeşil}{st.st_size} B{Bitir}")
    print(f"  {Beyaz}MIME(magic) :{Bitir} {Yeşil}{_magic_type(path)}{Bitir}")

    h = _hashes(path)
    print(f"  {Beyaz}MD5         :{Bitir} {Cyan}{h['md5']}{Bitir}")
    print(f"  {Beyaz}SHA1        :{Bitir} {Cyan}{h['sha1']}{Bitir}")
    print(f"  {Beyaz}SHA256      :{Bitir} {Cyan}{h['sha256']}{Bitir}")
    print(f"  {Beyaz}SHA512      :{Bitir} {Cyan}{h['sha512']}{Bitir}")

    ext = p.suffix.lower()
    if ext in {".jpg", ".jpeg", ".png", ".webp", ".gif", ".tiff", ".bmp"}:
        print(f"\n{Sarı}[*]{Bitir} Resim metadata...")
        _image(path)
    elif ext == ".pdf":
        print(f"\n{Sarı}[*]{Bitir} PDF metadata...")
        _pdf(path)
    elif ext in {".mp3", ".wav", ".flac", ".m4a", ".mp4", ".mkv", ".avi", ".mov"}:
        print(f"\n{Sarı}[*]{Bitir} Medya metadata...")
        _media(path)
    elif ext == ".zip":
        print(f"\n{Sarı}[*]{Bitir} Zip içeriği...")
        _zip(path)
    elif ext in {".tar", ".gz", ".tgz"}:
        print(f"\n{Sarı}[*]{Bitir} Tar içeriği...")
        _tar(path)

    if st.st_size <= 5 * 1024 * 1024:
        try:
            with open(path, "rb") as f:
                blob = f.read()
            iocs = _extract_iocs(blob)
            if any(iocs.values()):
                print(f"\n{Sarı}[*]{Bitir} IOC extraction:")
                for k, v in iocs.items():
                    if v:
                        print(f"  {Beyaz}{k:<7}:{Bitir} {Cyan}{'; '.join(v[:5])}{Bitir}")
        except OSError:
            pass