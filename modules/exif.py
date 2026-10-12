#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""EXIF extractor — her türlü görüntü metadata'sını çıkarır.

Backend öncelik sırası:
  1. exiftool   — en kapsamlı (external binary)
  2. exifread   — saf Python, hafif
  3. Pillow     — opsiyonel, Python

Backend yoksa ARGUS otomatik kurulum teklif eder (core.tools).

Çıktı kategorileri:
  File, Image, Camera, Exposure, Date, GPS, XMP, IPTC, ICC, Maker, Other
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core.deps import has
from core.security import is_safe_path


# ===== BACKEND SEÇİMİ =====

def _backend():
    if shutil.which("exiftool"):
        return "exiftool"
    if has("exifread"):
        return "exifread"
    if has("PIL"):
        return "pillow"
    return None


# ===== EXIFTOOL =====

def _extract_exiftool(path):
    try:
        res = subprocess.run(
            ["exiftool", "-j", "-G1", "-a", "-u", "-struct", path],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return None, str(e)

    if res.returncode != 0:
        return None, res.stderr.strip() or "exiftool error"

    try:
        data = json.loads(res.stdout)
    except (ValueError, json.JSONDecodeError) as e:
        return None, f"json parse: {e}"

    return (data[0] if data else {}), None


# ===== EXIFREAD =====

def _extract_exifread(path):
    try:
        import exifread
    except ImportError:
        return None, "exifread not installed"

    try:
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=True)
    except Exception as e:
        return None, str(e)

    out = {}
    for key, val in tags.items():
        out[str(key)] = str(val)
    return out, None


# ===== PILLOW =====

def _extract_pillow(path):
    try:
        from PIL import Image, ExifTags
    except ImportError:
        return None, "Pillow not installed"

    try:
        with Image.open(path) as im:
            out = {}
            out["Image Format"] = im.format or ""
            out["Image Size"] = f"{im.size[0]}x{im.size[1]}"
            out["Image Mode"] = im.mode

            exif = im.getexif() or {}
            for tag_id, val in exif.items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id))
                out[name] = str(val)
    except Exception as e:
        return None, str(e)

    return out, None


# ===== GPS =====

def _parse_gps_from_pillow(path):
    try:
        from PIL import Image, ExifTags
    except ImportError:
        return None

    try:
        with Image.open(path) as im:
            exif = im.getexif() or {}
            gps_ifd = None
            try:
                gps_ifd = exif.get_ifd(0x8825)
            except Exception:
                pass
            if not gps_ifd:
                return None

            gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
            lat_raw = gps.get("GPSLatitude")
            lon_raw = gps.get("GPSLongitude")
            lat_ref = gps.get("GPSLatitudeRef", "N")
            lon_ref = gps.get("GPSLongitudeRef", "E")
            alt = gps.get("GPSAltitude")

            if not lat_raw or not lon_raw:
                return None

            def to_deg(val):
                try:
                    d, m, s = (float(x) for x in val)
                    return d + m / 60 + s / 3600
                except (TypeError, ValueError):
                    try:
                        return float(val)
                    except (TypeError, ValueError):
                        return None

            lat = to_deg(lat_raw)
            lon = to_deg(lon_raw)
            if lat is None or lon is None:
                return None
            if lat_ref in ("S", "s"):
                lat = -lat
            if lon_ref in ("W", "w"):
                lon = -lon

            out = {"lat": lat, "lon": lon}
            if alt is not None:
                try:
                    out["alt"] = float(alt)
                except (TypeError, ValueError):
                    pass
            return out
    except Exception:
        return None


def _to_decimal(v):
    """'41 deg 1\\' 23.45" N' veya '41, 1, 23.45' veya '41.023' parse et."""
    s = str(v).strip()

    m = re.match(r"(\d+)\s*deg\s*(\d+)'\s*([\d.]+)\"", s)
    if m:
        try:
            d, mm, sec = float(m.group(1)), float(m.group(2)), float(m.group(3))
            return d + mm / 60 + sec / 3600
        except ValueError:
            return None

    parts = [p.strip() for p in s.replace("deg", "").replace("'", "")
             .replace('"', "").split(",")]
    try:
        nums = [float(p) for p in parts if p]
    except ValueError:
        nums = []
    if len(nums) == 3:
        return nums[0] + nums[1] / 60 + nums[2] / 3600
    if len(nums) == 1:
        return nums[0]
    return None


def _extract_gps_from_tags(tags):
    lat = lon = alt = None
    for k, v in tags.items():
        kl = str(k).lower()
        if "gpslatitude" in kl and "ref" not in kl:
            lat = _to_decimal(v)
        elif "gpslongitude" in kl and "ref" not in kl:
            lon = _to_decimal(v)
        elif "gpsaltitude" in kl:
            try:
                alt = float(str(v).split()[0])
            except (ValueError, IndexError):
                pass
    if lat is None or lon is None:
        return None
    out = {"lat": lat, "lon": lon}
    if alt is not None:
        out["alt"] = alt
    return out


# ===== SINIFLANDIRMA =====

def _categorize(tags):
    cats = {
        "File":     {},
        "Image":    {},
        "Camera":   {},
        "Exposure": {},
        "Date":     {},
        "GPS":      {},
        "XMP":      {},
        "IPTC":     {},
        "ICC":      {},
        "Maker":    {},
        "Other":    {},
    }

    for k, v in tags.items():
        key = str(k)
        kl = key.lower()

        if key.startswith("File:") or "filename" in kl or "filesize" in kl:
            cats["File"][key] = v
        elif key.startswith("GPS"):
            cats["GPS"][key] = v
        elif key.startswith("XMP"):
            cats["XMP"][key] = v
        elif key.startswith("IPTC"):
            cats["IPTC"][key] = v
        elif key.startswith("ICC"):
            cats["ICC"][key] = v
        elif "makernote" in kl:
            cats["Maker"][key] = v
        elif any(x in kl for x in ("make", "model", "lens", "serial",
                                    "software", "camera")):
            cats["Camera"][key] = v
        elif any(x in kl for x in ("exposure", "fnumber", "iso", "aperture",
                                    "focal", "shutter", "flash", "metering",
                                    "whitebalance", "exposuretime")):
            cats["Exposure"][key] = v
        elif any(x in kl for x in ("date", "time", "created", "modified")):
            cats["Date"][key] = v
        elif any(x in kl for x in ("image", "width", "height", "orientation",
                                    "resolution", "color", "bit")):
            cats["Image"][key] = v
        else:
            cats["Other"][key] = v

    return cats


# ===== HASH =====

def _file_hashes(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1 << 16)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except OSError:
        pass
    return {
        "MD5":    md5.hexdigest(),
        "SHA1":   sha1.hexdigest(),
        "SHA256": sha256.hexdigest(),
    }


# ===== ÇIKTI =====

def _print_category(name, tags, indent=2, limit=40):
    if not tags:
        return
    pad = " " * indent
    print(f"\n  {Sarı}[{name}]{Bitir} {Mor}({len(tags)} tag){Bitir}")
    shown = 0
    for k, v in tags.items():
        if shown >= limit:
            print(f"  {pad}{Mor}... +{len(tags) - limit} daha{Bitir}")
            break
        key = str(k)[:40]
        val = str(v)
        if len(val) > 90:
            val = val[:87] + "..."
        print(f"  {pad}{Beyaz}{key:<40}{Bitir}: {Yeşil}{val}{Bitir}")
        shown += 1


def _save_thumbnail(path, backend, p):
    out_dir = "reports"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"thumb_{p.stem}.jpg")

    if backend == "exiftool":
        try:
            res = subprocess.run(
                ["exiftool", "-b", "-ThumbnailImage", path],
                capture_output=True, timeout=15,
            )
            if res.returncode == 0 and res.stdout:
                with open(out_path, "wb") as f:
                    f.write(res.stdout)
                print(f"\n  {Yeşil}[✓]{Bitir} Thumbnail: {Cyan}{out_path}{Bitir}")
                return
        except Exception:
            pass

    print(f"\n  {Mor}[i]{Bitir} Thumbnail alınamadı "
          f"(backend desteklemiyor olabilir).")


# ===== ANA =====

def run(path, save_thumb=False, json_output=False):
    print(f"\n============= {Yeşil}EXIF EXTRACTOR{Bitir} =============")

    if not path:
        print(f"{Kırmızı}[✗]{Bitir} Boş dosya yolu.")
        return

    if not os.path.exists(path):
        print(f"{Kırmızı}[✗]{Bitir} Dosya yok: {path}")
        return

    if not is_safe_path(path):
        print(f"{Kırmızı}[✗]{Bitir} Güvensiz yol.")
        return

    backend = _backend()

    # Backend yoksa otomatik kurulum teklif et
    if backend is None:
        print(f"{Kırmızı}[✗]{Bitir} Hiçbir EXIF backend bulunamadı.\n")
        print(f"{Sarı}[i]{Bitir} Otomatik kurulum teklif ediliyor...")

        try:
            from core import tools
            ok = tools.install("exiftool", confirm=True)
        except Exception as e:
            print(f"{Kırmızı}[✗]{Bitir} Otomatik kurulum hatası: {e}")
            ok = False

        if not ok:
            print(f"\n{Mor}[i]{Bitir} Manuel seçenekler:")
            print(f"    {Cyan}pip install exifread{Bitir}                (hafif, saf Python)")
            print(f"    {Cyan}pkg install exiftool{Bitir}               (Termux)")
            print(f"    {Cyan}apt install libimage-exiftool-perl{Bitir}  (Debian/Ubuntu)")
            print(f"    {Cyan}pip install Pillow{Bitir}                 (Python)")
            return

        backend = _backend()
        if backend is None:
            print(f"{Kırmızı}[✗]{Bitir} Kurulum sonrası hâlâ backend bulunamadı.")
            return

    print(f"{Sarı}[*]{Bitir} Backend: {Cyan}{backend}{Bitir}")

    p = Path(path)
    st = p.stat()
    print(f"{Sarı}[*]{Bitir} Dosya: {Beyaz}{p}{Bitir}\n")

    print(f"  {Beyaz}Ad          :{Bitir} {Yeşil}{p.name}{Bitir}")
    print(f"  {Beyaz}Uzantı      :{Bitir} {Yeşil}{p.suffix or '-'}{Bitir}")
    print(f"  {Beyaz}Boyut       :{Bitir} {Yeşil}{st.st_size:,} B{Bitir}")

    hashes = _file_hashes(path)
    for h, v in hashes.items():
        print(f"  {Beyaz}{h:<12}:{Bitir} {Cyan}{v}{Bitir}")

    # Backend'e göre çıkar
    tags = None
    err = None
    if backend == "exiftool":
        tags, err = _extract_exiftool(path)
    elif backend == "exifread":
        tags, err = _extract_exifread(path)
    elif backend == "pillow":
        tags, err = _extract_pillow(path)

    if err:
        print(f"\n{Kırmızı}[✗]{Bitir} Backend hatası: {err}")
        return
    if not tags:
        print(f"\n{Mor}[i]{Bitir} Bu dosyada EXIF/metadata bulunamadı.")
        return

    if json_output:
        print("\n" + json.dumps(tags, indent=2, default=str,
                               ensure_ascii=False))
        return

    cats = _categorize(tags)

    for cat_name in ["File", "Image", "Camera", "Exposure", "Date",
                     "GPS", "XMP", "IPTC", "ICC", "Maker", "Other"]:
        _print_category(cat_name, cats[cat_name])

    # GPS konum
    gps = _extract_gps_from_tags(tags)
    if not gps and backend == "pillow":
        gps = _parse_gps_from_pillow(path)

    if gps:
        print(f"\n  {Sarı}[GPS Konum]{Bitir}")
        print(f"  {Beyaz}Enlem       :{Bitir} {Yeşil}{gps['lat']:.6f}{Bitir}")
        print(f"  {Beyaz}Boylam      :{Bitir} {Yeşil}{gps['lon']:.6f}{Bitir}")
        if gps.get("alt"):
            print(f"  {Beyaz}Rakım       :{Bitir} {Yeşil}{gps['alt']:.1f} m{Bitir}")
        maps = f"https://www.google.com/maps?q={gps['lat']:.6f},{gps['lon']:.6f}"
        print(f"  {Beyaz}Google Maps :{Bitir} {Cyan}{maps}{Bitir}")

    if save_thumb:
        _save_thumbnail(path, backend, p)