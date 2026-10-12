#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Telefon istihbaratı — çok sağlayıcılı derin analiz + offline operatör DB."""

import re

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core.deps import has
from core import database as db
from providers import registry
from modules import search as search_provider

if has("phonenumbers"):
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone

_TYPE_MAP = {
    0: "Sabit Hat", 1: "Mobil (GSM)", 2: "Sabit/Mobil", 3: "Ücretsiz",
    4: "Premium", 5: "Paylaşımlı Maliyet", 6: "VOIP", 7: "Kişisel",
    8: "Pager", 9: "UAN", 10: "Sesli Mesaj",
}


# ===== TÜRKİYE OPERATÖR PREFIX VERİTABANI =====
# Kaynak: BTK (Bilgi Teknolojileri ve İletişim Kurumu) numara tahsis planı.
TR_PREFIXES = {
    # Turkcell
    "0501": "Turkcell", "0505": "Turkcell", "0506": "Turkcell",
    "0530": "Turkcell", "0531": "Turkcell", "0532": "Turkcell",
    "0533": "Turkcell", "0534": "Turkcell", "0535": "Turkcell",
    "0536": "Turkcell", "0537": "Turkcell", "0538": "Turkcell",
    "0539": "Turkcell",
    # Vodafone
    "0502": "Vodafone", "0503": "Vodafone", "0504": "Vodafone",
    "0541": "Vodafone", "0542": "Vodafone", "0543": "Vodafone",
    "0544": "Vodafone", "0545": "Vodafone", "0546": "Vodafone",
    "0547": "Vodafone", "0548": "Vodafone", "0549": "Vodafone",
    "0551": "Vodafone", "0552": "Vodafone", "0553": "Vodafone",
    "0554": "Vodafone", "0555": "Vodafone",
    # Türk Telekom
    "0500": "Türk Telekom", "0507": "Türk Telekom", "0508": "Türk Telekom",
    "0509": "Türk Telekom", "0540": "Türk Telekom", "0550": "Türk Telekom",
    # KKTC (Kuzey Kıbrıs)
    "0533": "Turkcell (KKTC)", "0548": "Türk Telekom (KKTC)",
}


def _tr_operator_from_prefix(number):
    """Numaranın ilk 4 hanesinden Türkiye operatörünü bulur (offline)."""
    digits = re.sub(r"\D", "", number)
    if digits.startswith("90"):
        digits = "0" + digits[2:]
    if not digits.startswith("0"):
        digits = "0" + digits
    prefix = digits[:4]
    return TR_PREFIXES.get(prefix)


def normalize(raw):
    digits = re.sub(r"\D", "", raw or "")
    if not digits:
        return ""
    if digits.startswith("0"):
        return "+90" + digits[1:]
    if digits.startswith("90") and len(digits) > 10:
        return "+" + digits
    if len(digits) == 10:
        return "+90" + digits
    if raw.startswith("+"):
        return raw
    return "+" + digits


# ===== TEKNİK ANALİZ =====

def _technical(number):
    if not has("phonenumbers"):
        print(f"  {Sarı}[!]{Bitir} phonenumbers kurulu değil — teknik analiz atlandı.")
        return None

    try:
        parsed = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException as e:
        print(f"  {Kırmızı}[✗]{Bitir} Parse edilemedi: {e}")
        return None

    if not phonenumbers.is_valid_number(parsed):
        print(f"  {Kırmızı}[✗]{Bitir} Numara geçersiz.")
        return None

    ntype = phonenumbers.number_type(parsed)
    lib_carrier = carrier.name_for_number(parsed, "tr") or "-"
    country = geocoder.description_for_number(parsed, "tr") or "-"

    print(f"  {Beyaz}Durum        :{Bitir} {Yeşil}GEÇERLİ{Bitir}")
    print(f"  {Beyaz}Hat Tipi     :{Bitir} {Yeşil}{_TYPE_MAP.get(ntype, 'Bilinmiyor')}{Bitir}")
    print(f"  {Beyaz}Ülke/Bölge   :{Bitir} {Yeşil}{country}{Bitir}")
    print(f"  {Beyaz}Operatör     :{Bitir} {Yeşil}{lib_carrier}{Bitir}")
    print(f"  {Beyaz}Zaman Dilimi :{Bitir} {Yeşil}{', '.join(timezone.time_zones_for_number(parsed)) or '-'}{Bitir}")
    print(f"  {Beyaz}Uluslararası :{Bitir} {Yeşil}{phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}{Bitir}")

    # Offline prefix çapraz kontrolü (Türkiye)
    digits = re.sub(r"\D", "", number)
    prefix = None
    prefix_op = None

    if digits.startswith("90") and len(digits) >= 12:
        prefix = "0" + digits[2:5]
    elif digits.startswith("0") and len(digits) >= 11:
        prefix = digits[:4]
    elif len(digits) >= 10:
        prefix = "0" + digits[:3]

    if prefix:
        prefix_op = TR_PREFIXES.get(prefix)
        if prefix_op:
            print(f"  {Beyaz}Prefix       :{Bitir} {Cyan}{prefix}{Bitir} → {Yeşil}{prefix_op}{Bitir}")
            if lib_carrier != "-" and prefix_op.lower() not in lib_carrier.lower() \
                    and lib_carrier.lower() not in prefix_op.lower():
                print(f"  {Sarı}⚠  Taşınmış olabilir "
                      f"(kütüphane: {lib_carrier}, prefix: {prefix_op}){Bitir}")

    return {
        "carrier": lib_carrier,
        "country": country,
        "line_type": _TYPE_MAP.get(ntype),
        "prefix": prefix,
        "prefix_operator": prefix_op,
    }


# ===== IPQS =====

def _ipqs(number, country=None):
    p = registry.get("ipqualityscore")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} IPQualityScore (fraud / VoIP / prepaid)...")
    try:
        j = p.query(number, country=country)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} IPQS: {e}")
        return

    fraud = j.get("fraud_score", 0)
    color = Kırmızı if fraud > 66 else (Sarı if fraud > 33 else Yeşil)
    print(f"  {Beyaz}Fraud Score   :{Bitir} {color}{fraud}/100{Bitir}")
    print(f"  {Beyaz}Riskli        :{Bitir} {Kırmızı if j.get('risky') else Yeşil}{j.get('risky', False)}{Bitir}")
    print(f"  {Beyaz}VoIP          :{Bitir} {Kırmızı if j.get('VOIP') else Yeşil}{j.get('VOIP', False)}{Bitir}")
    print(f"  {Beyaz}Prepaid       :{Bitir} {Sarı if j.get('prepaid') else Yeşil}{j.get('prepaid', False)}{Bitir}")
    print(f"  {Beyaz}Aktif         :{Bitir} {Yeşil if j.get('active') else Kırmızı}{j.get('active', False)}{Bitir}")
    if j.get("carrier"):
        print(f"  {Beyaz}Carrier       :{Bitir} {Yeşil}{j['carrier']}{Bitir}")
    if j.get("line_type"):
        print(f"  {Beyaz}Line Type     :{Bitir} {Yeşil}{j['line_type']}{Bitir}")
    if j.get("city"):
        print(f"  {Beyaz}City          :{Bitir} {Yeşil}{j['city']}{Bitir}")


# ===== HUDSON ROCK =====

def _hudsonrock(number):
    p = registry.get("hudsonrock")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} Hudson Rock (infostealer veritabanı)...")
    try:
        j = p.query(number)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} Hudson Rock: {e}")
        return

    msg = j.get("message", "")
    if msg and "not found" in msg.lower():
        print(f"  {Beyaz}Sonuç         :{Bitir} {Yeşil}Temiz (infostealer veritabanında yok){Bitir}")
        return

    stealers = j.get("stealers") or []
    if stealers:
        print(f"  {Beyaz}Sonuç         :{Bitir} {Kırmızı}⚠ {len(stealers)} infostealer kaydı{Bitir}")
        for s in stealers[:5]:
            print(f"  {Kırmızı}[{s.get('stealer', '?')}]{Bitir} "
                  f"{Yeşil}{s.get('computer_name', '?')}{Bitir} "
                  f"{Mor}({s.get('date_compromised', '?')[:10]}){Bitir}")
    else:
        print(f"  {Beyaz}Sonuç         :{Bitir} {Yeşil}Temiz{Bitir}")


# ===== TELLOWS =====

def _tellows(number):
    p = registry.get("tellows")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} Tellows (spam / şikayet veritabanı)...")
    try:
        j = p.query(number)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} Tellows: {e}")
        return

    score = j.get("score")
    complaints = j.get("complaints", 0)
    cats = j.get("categories", [])

    if score is None and complaints == 0 and not cats:
        print(f"  {Beyaz}Sonuç         :{Bitir} {Yeşil}Veri yok (bu numara bildirilmemiş){Bitir}")
        return

    if score is not None:
        color = Kırmızı if score >= 7 else (Sarı if score >= 4 else Yeşil)
        print(f"  {Beyaz}Spam Skoru    :{Bitir} {color}{score}/9{Bitir}")
    if complaints:
        print(f"  {Beyaz}Şikayet       :{Bitir} {Sarı}{complaints}{Bitir}")
    if cats:
        print(f"  {Beyaz}Kategoriler   :{Bitir} {Cyan}{', '.join(cats)}{Bitir}")


# ===== NUMLOOKUPAPI =====

def _numlookupapi(number):
    p = registry.get("numlookupapi")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} NumLookupAPI (operatör / konum)...")
    try:
        j = p.query(number)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} NumLookupAPI: {e}")
        return
    for label, key in [
        ("Ülke", "country_name"), ("Ülke Kodu", "country_code"),
        ("Operatör", "carrier"), ("Hat Tipi", "line_type"),
        ("Konum", "location"),
    ]:
        v = j.get(key)
        if v:
            print(f"  {Beyaz}{label:<12}:{Bitir} {Yeşil}{v}{Bitir}")


# ===== HLR LOOKUP =====

def _hlrlookup(number):
    p = registry.get("hlrlookup")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} HLR Lookup (canlı ağ / taşınmışlık)...")
    try:
        j = p.query(number)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} HLR Lookup: {e}")
        return

    for label, key in [
        ("Durum", "status"), ("Aktif", "active"),
        ("Gerçek Operatör", "current_carrier"),
        ("Orijinal Operatör", "original_carrier"),
        ("Taşınmış", "ported"), ("Taşınma Tarihi", "last_ported_date"),
        ("Dolaşımda", "roaming"),
        ("Ülke", "country"), ("Ağ", "network"),
    ]:
        v = j.get(key)
        if v is not None and v != "":
            color = Yeşil
            if key in ("ported", "roaming") and v:
                color = Kırmızı
            if key == "active" and not v:
                color = Kırmızı
            print(f"  {Beyaz}{label:<18}:{Bitir} {color}{v}{Bitir}")


# ===== TELEGRAM =====

def _telegram(number):
    p = registry.get("telegram_check")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} Telegram kayıt kontrolü...")
    try:
        j = p.query(number)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} Telegram: {e}")
        return

    raw = j.get("raw", "")
    if not raw:
        print(f"  {Mor}[i]{Bitir} Sonuç yok.")
        return

    import json
    try:
        data = json.loads(raw)
        if isinstance(data, list) and data:
            entry = data[0]
            for label, key in [
                ("Kullanıcı Adı", "username"), ("Ad", "first_name"),
                ("Soyad", "last_name"), ("ID", "id"),
                ("Premium", "premium"), ("Bot", "bot"),
            ]:
                v = entry.get(key)
                if v:
                    print(f"  {Beyaz}{label:<14}:{Bitir} {Yeşil}{v}{Bitir}")
        else:
            print(f"  {Mor}[i]{Bitir} Ham çıktı: {raw[:200]}")
    except (ValueError, json.JSONDecodeError):
        if "not found" in raw.lower() or "error" in raw.lower():
            print(f"  {Beyaz}Sonuç         :{Bitir} {Yeşil}Telegram'da kayıtlı değil{Bitir}")
        else:
            print(f"  {Mor}[i]{Bitir} Ham çıktı: {raw[:300]}")


# ===== MESAJLAŞMA DEEP LINK =====

def _messaging_links(number):
    clean = number.replace("+", "")
    print(f"\n{Sarı}[*]{Bitir} Mesajlaşma platformları (deep link)...")
    print(f"  {Beyaz}[ WhatsApp ]{Bitir} {Cyan}https://wa.me/{clean}{Bitir}")
    print(f"  {Beyaz}[ Viber    ]{Bitir} {Cyan}viber://chat?number=%2B{clean}{Bitir}")
    print(f"  {Beyaz}[ Signal   ]{Bitir} {Cyan}sgnl://signal.me/#p/+{clean}{Bitir}")


# ===== SOSYAL MEDYA + ŞİKAYET SİTELERİ + BING FALLBACK =====

def _search_one(query, max_results=2):
    """Önce DDG, boşsa Bing fallback."""
    results = search_provider.search(query, max_results=max_results)
    if results:
        return results, "ddg"
    bing = registry.get("bing_search")
    if bing and getattr(bing, "enabled", True):
        try:
            results = bing.query(query, max_results=max_results)
            return results, "bing"
        except Exception:
            pass
    return [], None


def _social(number):
    clean = number.replace("+", "")

    # Türkiye'de 0'lı form (şikayet siteleri genelde böyle arar)
    if clean.startswith("90"):
        tr_form = "0" + clean[2:]
    else:
        tr_form = clean

    print(f"\n{Sarı}[*]{Bitir} Sosyal medya + şikayet siteleri taraması...")

    targets = {
        "Instagram":    f'site:instagram.com "{number}" OR "{clean}"',
        "Twitter/X":    f'site:twitter.com "{number}" OR "{clean}"',
        "Facebook":     f'site:facebook.com "{number}" OR "{clean}"',
        "Pastebin":     f'site:pastebin.com "{clean}"',
        "Şikayetvar":   f'site:sikayetvar.com "{tr_form}" OR "{clean}"',
        "Tellows TR":   f'site:tellows.com "{clean}"',
        "NumaraRaporu": f'site:numaraporu.com "{clean}"',
    }

    for platform, q in targets.items():
        results, src = _search_one(q, max_results=2)
        if not results:
            print(f"  {Beyaz}[ {Mor}UNKNOWN {Beyaz}]{Bitir} {platform}")
            continue
        tag = f"via {src}" if src else ""
        for url in results:
            print(f"  {Beyaz}[ {Yeşil}FOUND   {Beyaz}]{Bitir} {platform:<14} "
                  f"{Yeşil}{url}{Bitir} {Mor}{tag}{Bitir}")


# ===== CORRELATION =====

def _correlate(number, technical_data=None):
    try:
        db.add_entity("phone", number, data=technical_data or {},
                      source="phone_module", confidence="VERIFIED")
        if technical_data:
            carrier_name = technical_data.get("carrier")
            country = technical_data.get("country")
            prefix_op = technical_data.get("prefix_operator")
            if carrier_name and carrier_name != "-":
                db.add_entity("carrier", carrier_name, source="phone_module",
                              confidence="LIKELY")
                db.add_relation(number, carrier_name, "belongs_to_carrier",
                                evidence="phonenumbers")
            if prefix_op and prefix_op != carrier_name:
                db.add_entity("carrier", prefix_op, source="tr_prefix_db",
                              confidence="LIKELY")
                db.add_relation(number, prefix_op, "prefix_hint",
                                evidence="BTK tahsis planı")
            if country:
                db.add_entity("country", country, source="phone_module",
                              confidence="VERIFIED")
                db.add_relation(number, country, "registered_in",
                                evidence="phonenumbers")
    except Exception:
        pass

    try:
        rels = db.get_relations(limit=500)
        matched = [r for r in rels if r[0] == number or r[1] == number]
    except Exception:
        return
    if not matched:
        print(f"\n  {Mor}[i]{Bitir} Kayıtlı ilişki yok — bu numara için ilk sorgu.")
        return

    print()
    print(f"  {Cyan}┌─[ {Yeşil}İlişkiler{ Cyan} ]─────────────────────────────────────────┐{Bitir}")
    for src, dst, kind, ev, ts in matched[:15]:
        print(f"  {Cyan}│{Bitir} {Yeşil}{src}{Bitir}  {Cyan}─[{Sarı}{kind}{Cyan}]→{Bitir}  {Yeşil}{dst}{Bitir}")
    if len(matched) > 15:
        print(f"  {Cyan}│{Bitir} {Mor}... +{len(matched) - 15} daha{Bitir}")
    print(f"  {Cyan}└──────────────────────────────────────────────────────────┘{Bitir}")


# ===== ANA =====

def run(raw):
    print(f"\n============= {Yeşil}DEEP PHONE ANALYSIS{Bitir} =============")

    number = normalize(raw)
    if not number or len(re.sub(r"\D", "", number)) < 7:
        print(f"{Kırmızı}[✗]{Bitir} Geçersiz numara.")
        return

    print(f"{Sarı}[*]{Bitir} Normalize: {Beyaz}{number}{Bitir}\n")

    technical = _technical(number) or {}
    _ipqs(number)
    _hudsonrock(number)
    _tellows(number)
    _numlookupapi(number)
    _hlrlookup(number)
    _telegram(number)
    _messaging_links(number)
    _social(number)
    _correlate(number, technical)