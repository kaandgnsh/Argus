#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Threat Intelligence — IOC tipine göre otomatik yönlendirme.

Desteklenen IOC tipleri:
  - IPv4/IPv6   : URLhaus, OTX, Tor exit, threatfox
  - Domain      : URLhaus, OTX, urlscan, threatfox
  - URL         : URLhaus, urlscan, Wayback
  - Hash        : MalwareBazaar, OTX
  - CVE         : NVD, CISA KEV, EPSS
"""

import ipaddress
import re

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core import database as db
from providers import registry


HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def _detect_ioc_type(value):
    v = value.strip()
    if CVE_RE.match(v):
        return "cve"
    if HASH_RE.match(v):
        return "hash"
    if v.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "." in v and " " not in v:
        return "domain"
    return "unknown"


# ===== IP =====

def _threat_ip(ip):
    p = registry.get("urlhaus")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} URLhaus host lookup...")
        try:
            j = p.query(ip)
            qs = j.get("query_status")
            if qs == "no_results":
                print(f"  {Yeşil}[✓]{Bitir} URLhaus'ta kayıtlı değil.")
            else:
                print(f"  {Beyaz}Status       :{Bitir} {Yeşil}{qs}{Bitir}")
                for u in (j.get("urls") or [])[:5]:
                    print(f"  {Cyan}{u.get('url')}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} URLhaus: {e}")

    p = registry.get("otx")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} AlienVault OTX...")
        try:
            j = p.query("IPv4", ip)
            print(f"  {Beyaz}Pulse count  :{Bitir} {Yeşil}{j.get('pulse_count')}{Bitir}")
            print(f"  {Beyaz}Reputation   :{Bitir} {Yeşil}{j.get('reputation')}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} OTX: {e}")

    p = registry.get("tor_exit")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} Tor exit node...")
        try:
            if p.is_exit(ip):
                print(f"  {Kırmızı}⚠ Tor exit node{Bitir}")
            else:
                print(f"  {Yeşil}[✓]{Bitir} Tor exit değil.")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} Tor: {e}")

    p = registry.get("threatfox")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} ThreatFox (malware/C2 IOC)...")
        try:
            j = p.query(ip)
            data = j.get("data") or []
            if not data:
                print(f"  {Yeşil}[✓]{Bitir} ThreatFox'ta kayıtlı değil.")
            else:
                print(f"  {Kırmızı}{len(data)} IOC eşleşmesi{Bitir}")
                for entry in data[:5]:
                    malware = entry.get("malware_printable") or entry.get("malware", "?")
                    threat = entry.get("threat_type", "?")
                    print(f"  {Kırmızı}[{threat}]{Bitir} {Yeşil}{malware}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} ThreatFox: {e}")


# ===== DOMAIN =====

def _threat_domain(domain):
    p = registry.get("urlhaus")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} URLhaus host lookup...")
        try:
            j = p.query(domain)
            qs = j.get("query_status")
            if qs == "no_results":
                print(f"  {Yeşil}[✓]{Bitir} URLhaus'ta kayıtlı değil.")
            else:
                print(f"  {Beyaz}Status       :{Bitir} {Yeşil}{qs}{Bitir}")
                for u in (j.get("urls") or [])[:5]:
                    print(f"  {Cyan}{u.get('url')}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} URLhaus: {e}")

    p = registry.get("otx")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} AlienVault OTX...")
        try:
            j = p.query("domain", domain)
            print(f"  {Beyaz}Pulse count  :{Bitir} {Yeşil}{j.get('pulse_count')}{Bitir}")
            print(f"  {Beyaz}Reputation   :{Bitir} {Yeşil}{j.get('reputation')}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} OTX: {e}")

    p = registry.get("urlscan")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} urlscan.io...")
        try:
            j = p.query(f"domain:{domain}", size=5)
            results = j.get("results") or []
            if not results:
                print(f"  {Yeşil}[✓]{Bitir} urlscan.io'da taranmamış.")
            else:
                print(f"  {Beyaz}Taramalar    :{Bitir} {Yeşil}{len(results)}{Bitir}")
                for r_ in results[:5]:
                    page = r_.get("page") or {}
                    verdict = (r_.get("verdicts") or {}).get("overall") or {}
                    color = Kırmızı if verdict.get("malicious") else Yeşil
                    print(f"  {color}●{Bitir} {Cyan}{page.get('url', '?')[:80]}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} urlscan: {e}")

    p = registry.get("threatfox")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} ThreatFox...")
        try:
            j = p.query(domain)
            data = j.get("data") or []
            if not data:
                print(f"  {Yeşil}[✓]{Bitir} ThreatFox'ta kayıtlı değil.")
            else:
                print(f"  {Kırmızı}{len(data)} IOC eşleşmesi{Bitir}")
                for entry in data[:5]:
                    malware = entry.get("malware_printable") or entry.get("malware", "?")
                    print(f"  {Kırmızı}[{entry.get('threat_type', '?')}]{Bitir} {Yeşil}{malware}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} ThreatFox: {e}")


# ===== URL =====

def _threat_url(url):
    p = registry.get("urlhaus")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} URLhaus (URL lookup)...")
        try:
            r = p.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
            )
            if r.status_code == 401:
                print(f"  {Sarı}[i]{Bitir} URLhaus Auth-Key gerekli (ABUSECH_AUTH_KEY).")
            elif r.status_code == 200:
                j = r.json()
                qs = j.get("query_status")
                if qs == "no_results":
                    print(f"  {Yeşil}[✓]{Bitir} URLhaus'ta kayıtlı değil.")
                elif qs == "ok":
                    print(f"  {Kırmızı}⚠ MALWARE KAYDI VAR!{Bitir}")
                    if j.get("threat"):
                        print(f"  {Beyaz}Tehdit       :{Bitir} {Kırmızı}{j['threat']}{Bitir}")
                else:
                    print(f"  {Mor}[i]{Bitir} URLhaus: {qs}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} URLhaus: {e}")

    p = registry.get("urlscan")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} urlscan.io...")
        try:
            j = p.query(f'page.url:"{url}"', size=5)
            results = j.get("results") or []
            if not results:
                print(f"  {Yeşil}[✓]{Bitir} urlscan.io'da taranmamış.")
            else:
                print(f"  {Beyaz}Taramalar    :{Bitir} {Yeşil}{len(results)}{Bitir}")
                for r_ in results[:5]:
                    verdict = (r_.get("verdicts") or {}).get("overall") or {}
                    color = Kırmızı if verdict.get("malicious") else Yeşil
                    score = verdict.get("score", 0)
                    print(f"  {color}●{Bitir} skor: {score}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} urlscan: {e}")


# ===== HASH =====

def _threat_hash(h):
    print(f"\n{Sarı}[*]{Bitir} MalwareBazaar (hash lookup)...")
    p = registry.get("malwarebazaar")
    if p is None or not getattr(p, "enabled", True):
        print(f"  {Mor}[i]{Bitir} MalwareBazaar provider kapalı.")
    else:
        try:
            j = p.query(h)
            data = j.get("data") or []
            if not data:
                print(f"  {Yeşil}[✓]{Bitir} Bilinen malware değil.")
            else:
                entry = data[0]
                print(f"  {Kırmızı}⚠ MALWARE!{Bitir}")
                for label, key in [
                    ("İmza", "signature"), ("Dosya", "file_name"),
                    ("Dosya Tipi", "file_type_mime"), ("Boyut", "file_size"),
                    ("Eklenme", "first_seen"), ("Tags", "tags"),
                ]:
                    v = entry.get(key)
                    if v:
                        if isinstance(v, list):
                            v = ", ".join(str(x) for x in v[:5])
                        print(f"  {Beyaz}{label:<12}:{Bitir} {Kırmızı}{v}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} MalwareBazaar: {e}")

    p = registry.get("otx")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} AlienVault OTX...")
        try:
            j = p.query("file", h)
            print(f"  {Beyaz}Pulse count  :{Bitir} {Yeşil}{j.get('pulse_count')}{Bitir}")
            print(f"  {Beyaz}Reputation   :{Bitir} {Yeşil}{j.get('reputation')}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} OTX: {e}")


# ===== CVE =====

def _threat_cve(cve):
    cve = cve.upper()

    p = registry.get("nvd")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} NVD — National Vulnerability Database...")
        try:
            j = p.query(cve)
            if not j:
                print(f"  {Mor}[i]{Bitir} NVD'de bulunamadı.")
            else:
                if j.get("description"):
                    print(f"  {Beyaz}Açıklama     :{Bitir} {Yeşil}{j['description'][:200]}{Bitir}")
                cvss = j.get("cvss") or {}
                if cvss:
                    score = cvss.get("base_score")
                    sev = cvss.get("base_severity", "")
                    try:
                        sf = float(score) if score is not None else 0
                    except (TypeError, ValueError):
                        sf = 0
                    color = Kırmızı if sf >= 7 else (Sarı if sf >= 4 else Yeşil)
                    print(f"  {Beyaz}CVSS         :{Bitir} {color}{score} ({sev}){Bitir}")
                    if cvss.get("vector"):
                        print(f"  {Beyaz}Vector       :{Bitir} {Yeşil}{cvss['vector']}{Bitir}")
                cwes = j.get("cwe") or []
                if cwes:
                    print(f"  {Beyaz}CWE          :{Bitir} {Cyan}{', '.join(cwes)}{Bitir}")
                if j.get("published"):
                    print(f"  {Beyaz}Published    :{Bitir} {Yeşil}{j['published']}{Bitir}")
                refs = j.get("references") or []
                if refs:
                    print(f"  {Beyaz}Referanslar  :{Bitir}")
                    for r_ in refs[:4]:
                        print(f"    {Cyan}{r_[:100]}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} NVD: {e}")

    p = registry.get("cisa_kev")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} CISA KEV (Known Exploited Vulnerabilities)...")
        try:
            entry = p.lookup(cve)
            if entry:
                print(f"  {Kırmızı}⚠ KEV KATALOĞUNDA!{Bitir}")
                print(f"  {Beyaz}Vendor       :{Bitir} {Kırmızı}{entry.get('vendor')}{Bitir}")
                print(f"  {Beyaz}Product      :{Bitir} {Kırmızı}{entry.get('product')}{Bitir}")
                print(f"  {Beyaz}Eklendi      :{Bitir} {Yeşil}{entry.get('dateAdded')}{Bitir}")
                print(f"  {Beyaz}Deadline     :{Bitir} {Sarı}{entry.get('dueDate')}{Bitir}")
                rw = entry.get("ransomware_use")
                if rw and rw.lower() == "known":
                    print(f"  {Beyaz}Ransomware   :{Bitir} {Kırmızı}EVET — bilinen ransomware kampanyalarında kullanıldı{Bitir}")
                if entry.get("requiredAction"):
                    print(f"  {Beyaz}Aksiyon      :{Bitir} {Yeşil}{entry['requiredAction'][:200]}{Bitir}")
            else:
                print(f"  {Yeşil}[✓]{Bitir} CISA KEV kataloğunda yok.")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} CISA KEV: {e}")

    p = registry.get("epss")
    if p and getattr(p, "enabled", True):
        print(f"\n{Sarı}[*]{Bitir} EPSS (Exploit Prediction Scoring)...")
        try:
            j = p.query(cve)
            if not j:
                print(f"  {Mor}[i]{Bitir} EPSS verisi yok.")
            else:
                epss = j.get("epss", 0)
                percentile = j.get("percentile", 0)
                pct = f"{epss * 100:.2f}%"
                perc = f"{percentile * 100:.1f}th percentile"
                color = Kırmızı if epss >= 0.5 else (Sarı if epss >= 0.1 else Yeşil)
                print(f"  {Beyaz}EPSS         :{Bitir} {color}{pct} (önümüzdeki 30 gün içinde sömürülme olasılığı){Bitir}")
                print(f"  {Beyaz}Percentile   :{Bitir} {Yeşil}{perc}{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} EPSS: {e}")


# ===== CORRELATION =====

def _correlate(ioc, ioc_type):
    try:
        db.add_entity(ioc_type, ioc, source="threat_module", confidence="VERIFIED")
    except Exception:
        pass

    try:
        rels = db.get_relations(limit=500)
        matched = [r for r in rels if r[0] == ioc or r[1] == ioc]
    except Exception:
        return
    if not matched:
        return

    print()
    print(f"  {Cyan}┌─[ {Yeşil}İlişkiler{ Cyan} ]─────────────────────────────────────────┐{Bitir}")
    for src, dst, kind, ev, ts in matched[:10]:
        print(f"  {Cyan}│{Bitir} {Yeşil}{src}{Bitir}  {Cyan}─[{Sarı}{kind}{Cyan}]→{Bitir}  {Yeşil}{dst}{Bitir}")
    print(f"  {Cyan}└──────────────────────────────────────────────────────────┘{Bitir}")


# ===== ANA =====

def run(ioc):
    print(f"\n============= {Yeşil}THREAT INTELLIGENCE{Bitir} =============")

    if not ioc:
        print(f"{Kırmızı}[✗]{Bitir} Boş IOC.")
        return

    ioc = ioc.strip()
    ioc_type = _detect_ioc_type(ioc)

    type_label = {
        "ip": "IPv4/IPv6",
        "domain": "Domain",
        "url": "URL",
        "hash": "Hash",
        "cve": "CVE",
        "unknown": "Bilinmeyen",
    }[ioc_type]

    print(f"{Sarı}[*]{Bitir} IOC: {Beyaz}{ioc}{Bitir}")
    print(f"{Sarı}[*]{Bitir} Tip: {Cyan}{type_label}{Bitir}")

    if ioc_type == "ip":
        _threat_ip(ioc)
    elif ioc_type == "domain":
        _threat_domain(ioc)
    elif ioc_type == "url":
        _threat_url(ioc)
    elif ioc_type == "hash":
        _threat_hash(ioc)
    elif ioc_type == "cve":
        _threat_cve(ioc)
    else:
        print(f"{Kırmızı}[✗]{Bitir} IOC tipi tanınamadı.")
        return

    _correlate(ioc, ioc_type)