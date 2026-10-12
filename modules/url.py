#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""URL intelligence — redirect, TLS, fingerprint, threat, archive.

Kapsam:
  - URL parsing detayı (scheme, host, port, path, query, fragment)
  - Redirect zinciri (her hop: status, Location, süre)
  - Domain değişimi uyarısı
  - HTTP headers (güvenlik header'ları)
  - TLS sertifika detayı
  - Favicon SHA256
  - Cookie analizi (Secure, HttpOnly, SameSite)
  - CSP parse (izin verilen domainler)
  - URL shortener expansion
  - Wayback Machine snapshot kontrolü
  - URLhaus (abuse.ch) malware kontrolü
  - urlscan.io tarama kontrolü
  - Homoglyph/typosquat uyarısı
  - HTTP desteklenen metodlar
  - Tracking parametresi tespiti
  - Correlation DB
"""

import hashlib
import re
import socket
import ssl
import time
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

from bs4 import BeautifulSoup

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core.http import safe_get, UnsafeURL, _session
from core import database as db
from providers import registry


# Yaygın kısa link servisleri
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "tiny.cc",
    "shorturl.at", "rebrand.ly", "cutt.ly", "rb.gy", "t.ly",
    "s.id", "lnkd.in", "x.co", "v.gd", "short.link", "kutt.it",
}

# Tracking parametreleri
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "dclid", "msclkid", "yclid", "twclid",
    "_ga", "_gl", "mc_eid", "mc_cid", "ref", "ref_src", "ref_url",
    "source", "campaign", "medium", "igshid", "si", "s_kwcid",
}


def _parse_full(url):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    return {
        "scheme": p.scheme,
        "host": p.hostname,
        "port": p.port,
        "path": p.path,
        "query": p.query,
        "fragment": p.fragment,
        "params": qs,
        "username": p.username,
        "password": p.password,
    }


def _clean_url(url):
    """Tracking parametrelerini kaldırır."""
    p = urlparse(url)
    if not p.query:
        return url, []

    qs = parse_qs(p.query, keep_blank_values=True)
    removed = []
    for k in list(qs.keys()):
        if k.lower() in TRACKING_PARAMS:
            removed.append(k)
            del qs[k]

    new_query = urlencode(qs, doseq=True)
    cleaned = urlunparse((
        p.scheme, p.netloc, p.path, p.params, new_query, p.fragment,
    ))
    return cleaned, removed


def _is_shortener(host):
    if not host:
        return False
    h = host.lower().lstrip("www.")
    return any(h == s or h.endswith("." + s) for s in SHORTENERS)


def _detect_typosquat(host):
    """Basit typosquat uyarısı — ünlü domainlerin yakın yazımı."""
    if not host:
        return None
    h = host.lower().lstrip("www.")

    # Rakam-harf değişimleri: goog1e.com -> google.com
    subs = {
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    }
    deobf = h
    for digit, letter in subs.items():
        deobf = deobf.replace(digit, letter)

    famous = {
        "google.com", "youtube.com", "facebook.com", "twitter.com",
        "instagram.com", "github.com", "microsoft.com", "apple.com",
        "amazon.com", "netflix.com", "linkedin.com", "reddit.com",
        "wikipedia.org", "paypal.com", "whatsapp.com", "telegram.org",
        "gmail.com", "outlook.com", "yahoo.com", "icloud.com",
        "binance.com", "coinbase.com", "instagram.com",
    }
    if deobf in famous and h != deobf:
        return deobf

    # Harf karışıklıkları: rn -> m, vv -> w
    if h != deobf:
        deobf2 = deobf.replace("rn", "m").replace("vv", "w")
        if deobf2 in famous:
            return deobf2

    return None


# ===== URL PARSING =====

def _url_parse_section(url):
    print(f"{Sarı}[*]{Bitir} URL yapısı...")
    info = _parse_full(url)
    for label, key in [
        ("Scheme", "scheme"), ("Host", "host"), ("Port", "port"),
        ("Path", "path"), ("Query", "query"), ("Fragment", "fragment"),
    ]:
        v = info.get(key)
        if v is not None and v != "":
            print(f"  {Beyaz}{label:<12}:{Bitir} {Yeşil}{v}{Bitir}")

    if info.get("params"):
        print(f"  {Beyaz}Params      :{Bitir}")
        for k, vals in info["params"].items():
            v = vals[0] if vals else ""
            marker = ""
            if k.lower() in TRACKING_PARAMS:
                marker = f" {Sarı}[tracking]{Bitir}"
            print(f"    {Cyan}{k}{Bitir} = {Yeşil}{v[:60]}{Bitir}{marker}")

    return info


# ===== REDIRECT ZİNCİRİ =====

def _redirect_chain(url):
    print(f"\n{Sarı}[*]{Bitir} Redirect zinciri...")
    try:
        session = _session()
        r = session.get(url, timeout=10, allow_redirects=True)
    except UnsafeURL as e:
        print(f"  {Kırmızı}[✗]{Bitir} SSRF koruması: {e}")
        return None
    except Exception as e:
        print(f"  {Kırmızı}[✗]{Bitir} Bağlantı hatası: {e}")
        return None

    hops = []
    if r.history:
        start_host = urlparse(url).hostname
        for h in r.history:
            hop_host = urlparse(h.url).hostname
            flag = ""
            if hop_host and start_host and hop_host != start_host:
                flag = f" {Sarı}⚠ domain değişti{Bitir}"
            hops.append((h.status_code, h.url, flag))

        print(f"  {Beyaz}Toplam      :{Bitir} {Yeşil}{len(r.history)} redirect{Bitir}")
        for i, (code, u, flag) in enumerate(hops, 1):
            print(f"  {Mor}{i:>2}.{Bitir} [{code}] {Cyan}{u[:90]}{Bitir}{flag}")
    else:
        print(f"  {Yeşil}[✓]{Bitir} Redirect yok (doğrudan yanıt).")

    print(f"  {Beyaz}Final       :{Bitir} {Yeşil}{r.url}{Bitir}")
    print(f"  {Beyaz}Status      :{Bitir} {Yeşil}{r.status_code}{Bitir}")

    return r


# ===== HEADERS =====

def _headers_section(r):
    print(f"\n{Sarı}[*]{Bitir} HTTP headers...")
    important = [
        "Server", "X-Powered-By", "Content-Type", "Content-Length",
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy",
        "CF-Ray", "X-Vercel-Id", "X-Amz-Cf-Id", "Via",
    ]
    for h in important:
        v = r.headers.get(h)
        if v:
            val = v[:90] + ("..." if len(v) > 90 else "")
            print(f"  {Beyaz}{h:<28}:{Bitir} {Yeşil}{val}{Bitir}")


# ===== CSP PARSE =====

def _csp_parse(r):
    csp = r.headers.get("Content-Security-Policy")
    if not csp:
        return
    print(f"\n{Sarı}[*]{Bitir} CSP analizi...")

    # directives: default-src 'self'; script-src ...
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if len(tokens) >= 2:
            directives[tokens[0]] = tokens[1:]

    interesting = ["default-src", "script-src", "connect-src", "img-src",
                   "style-src", "frame-ancestors"]
    for d in interesting:
        if d in directives:
            vals = directives[d]
            preview = " ".join(vals[:6])
            if len(vals) > 6:
                preview += f" (+{len(vals) - 6})"
            print(f"  {Beyaz}{d:<16}:{Bitir} {Yeşil}{preview}{Bitir}")

    # Zayıf CSP uyarısı
    if "script-src" in directives and "'unsafe-inline'" in directives["script-src"]:
        print(f"  {Sarı}⚠  script-src 'unsafe-inline' içeriyor (XSS riski artar){Bitir}")
    if "script-src" in directives and "'unsafe-eval'" in directives["script-src"]:
        print(f"  {Sarı}⚠  script-src 'unsafe-eval' içeriyor (kod injection riski){Bitir}")


# ===== COOKIES =====

def _cookies_analysis(r):
    cookies = r.cookies
    if not cookies:
        return
    print(f"\n{Sarı}[*]{Bitir} Cookie analizi ({len(cookies)} çerez)...")

    for c in list(cookies)[:15]:
        flags = []
        if c.secure:
            flags.append("Secure")
        if c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly"):
            flags.append("HttpOnly")
        samesite = None
        for k in ("SameSite", "samesite"):
            v = c.get_nonstandard_attr(k)
            if v:
                samesite = v
                break
        if samesite:
            flags.append(f"SameSite={samesite}")

        flag_str = f" {Mor}[{', '.join(flags)}]{Bitir}" if flags else f" {Sarı}[no flags]{Bitir}"
        print(f"  {Beyaz}{c.name[:30]:<30}{Bitir}{flag_str}")

    # İç çerez güvenlik kontrolü
    insecure = [c.name for c in cookies if not c.secure]
    no_httponly = [c.name for c in cookies
                   if not c.has_nonstandard_attr("HttpOnly")
                   and not c.has_nonstandard_attr("httponly")]
    if insecure:
        print(f"  {Sarı}⚠  Secure flag'i olmayan çerezler: {', '.join(insecure[:5])}{Bitir}")
    if no_httponly:
        print(f"  {Sarı}⚠  HttpOnly olmayan: {', '.join(no_httponly[:5])}{Bitir}")


# ===== TLS =====

def _tls_info(host):
    print(f"\n{Sarı}[*]{Bitir} TLS sertifika bilgisi...")
    version = cipher = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} TLS: {e}")
        return

    if version:
        print(f"  {Beyaz}TLS Version  :{Bitir} {Yeşil}{version}{Bitir}")
    if cipher:
        print(f"  {Beyaz}Cipher       :{Bitir} {Yeşil}{cipher[0]}{Bitir}")

    cert = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception:
        pass

    if not cert:
        return

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    print(f"  {Beyaz}Subject CN   :{Bitir} {Yeşil}{subject.get('commonName', '?')}{Bitir}")
    print(f"  {Beyaz}Issuer       :{Bitir} {Yeşil}{issuer.get('organizationName', issuer.get('commonName', '?'))}{Bitir}")
    print(f"  {Beyaz}Valid From   :{Bitir} {Yeşil}{cert.get('notBefore', '?')}{Bitir}")
    print(f"  {Beyaz}Valid Until  :{Bitir} {Yeşil}{cert.get('notAfter', '?')}{Bitir}")


# ===== FAVICON =====

def _favicon(r):
    print(f"\n{Sarı}[*]{Bitir} Favicon hash...")
    base = f"{urlparse(r.url).scheme}://{urlparse(r.url).netloc}"
    for path in ("/favicon.ico", "/favicon.png"):
        try:
            fr = safe_get(base + path, timeout=6)
            if fr.status_code == 200 and len(fr.content) > 0:
                h = hashlib.sha256(fr.content).hexdigest()
                print(f"  {Beyaz}URL          :{Bitir} {Yeşil}{base + path}{Bitir}")
                print(f"  {Beyaz}Size         :{Bitir} {Yeşil}{len(fr.content)} B{Bitir}")
                print(f"  {Beyaz}SHA256       :{Bitir} {Cyan}{h}{Bitir}")
                return
        except Exception:
            continue
    print(f"  {Mor}[i]{Bitir} Favicon alınamadı.")


# ===== HTTP METODLARI =====

def _http_methods(r):
    print(f"\n{Sarı}[*]{Bitir} HTTP metodları (OPTIONS)...")
    try:
        base = f"{urlparse(r.url).scheme}://{urlparse(r.url).netloc}"
        opts = _session().options(base, timeout=8)
        allow = opts.headers.get("Allow") or opts.headers.get("allow")
        if allow:
            print(f"  {Beyaz}Allow        :{Bitir} {Yeşil}{allow}{Bitir}")
        else:
            print(f"  {Mor}[i]{Bitir} OPTIONS yanıtında Allow header yok.")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} OPTIONS: {e}")


# ===== TRACKING PARAMS =====

def _tracking_section(url):
    cleaned, removed = _clean_url(url)
    if not removed:
        return
    print(f"\n{Sarı}[*]{Bitir} Tracking parametreleri...")
    print(f"  {Beyaz}Tespit       :{Bitir} {Sarı}{', '.join(removed)}{Bitir}")
    if cleaned != url:
        print(f"  {Beyaz}Temiz URL    :{Bitir} {Cyan}{cleaned[:100]}{Bitir}")


# ===== SHORTENER =====

def _shortener_section(url, r):
    host = urlparse(url).hostname
    if not _is_shortener(host):
        return
    print(f"\n{Sarı}[*]{Bitir} URL shortener tespit edildi: {Kırmızı}{host}{Bitir}")
    if r.history:
        final = r.url
        print(f"  {Beyaz}Açılmış URL  :{Bitir} {Yeşil}{final}{Bitir}")
    else:
        print(f"  {Mor}[i]{Bitir} Expansion yapılamadı.")


# ===== TYPOSQUAT =====

def _typosquat_section(url):
    host = urlparse(url).hostname
    if not host:
        return
    sug = _detect_typosquat(host)
    if sug:
        print(f"\n{Sarı}⚠  Typosquat uyarısı{ Bitir}")
        print(f"  {Beyaz}Şüpheli host :{Bitir} {Kırmızı}{host}{Bitir}")
        print(f"  {Beyaz}Olası hedef  :{Bitir} {Yeşil}{sug}{Bitir}")


# ===== WAYBACK =====

def _wayback(url):
    print(f"\n{Sarı}[*]{Bitir} Wayback Machine...")
    p = registry.get("wayback")
    if p is None or not getattr(p, "enabled", True):
        print(f"  {Mor}[i]{Bitir} Wayback provider kapalı.")
        return
    try:
        snaps = p.snapshots(url, limit=30)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} Wayback: {e}")
        return

    if not snaps:
        print(f"  {Mor}[i]{Bitir} Arşiv snapshot'ı yok.")
        return

    print(f"  {Beyaz}Snapshot     :{Bitir} {Yeşil}{len(snaps)}{Bitir}")

    # İlk ve son tarih
    first = snaps[0].get("timestamp", "")[:8]
    last = snaps[-1].get("timestamp", "")[:8]
    if first:
        print(f"  {Beyaz}İlk          :{Bitir} {Yeşil}{first[:4]}-{first[4:6]}-{first[6:8]}{Bitir}")
    if last:
        print(f"  {Beyaz}Son          :{Bitir} {Yeşil}{last[:4]}-{last[4:6]}-{last[6:8]}{Bitir}")

    # Wayback URL'i
    if snaps:
        ts = snaps[-1].get("timestamp", "")
        if ts:
            print(f"  {Beyaz}Son snapshot :{Bitir} {Cyan}https://web.archive.org/web/{ts}/{url}{Bitir}")


# ===== URLHAUS =====

def _urlhaus_url(url):
    print(f"\n{Sarı}[*]{Bitir} URLhaus (URL malware kontrolü)...")
    p = registry.get("urlhaus")
    if p is None or not getattr(p, "enabled", True):
        print(f"  {Mor}[i]{Bitir} URLhaus provider kapalı.")
        return
    try:
        # URLhaus URL lookup endpoint'i
        r = p.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
        )
        if r.status_code == 401:
            print(f"  {Sarı}[i]{Bitir} URLhaus Auth-Key gerekli (ABUSECH_AUTH_KEY).")
            return
        if r.status_code != 200:
            print(f"  {Mor}[!]{Bitir} URLhaus: HTTP {r.status_code}")
            return
        j = r.json()
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} URLhaus: {e}")
        return

    qs = j.get("query_status")
    if qs == "no_results":
        print(f"  {Yeşil}[✓]{Bitir} URLhaus'ta kayıtlı değil.")
    elif qs == "ok":
        print(f"  {Kırmızı}⚠ MALWARE KAYDI VAR!{Bitir}")
        if j.get("threat"):
            print(f"  {Beyaz}Tehdit       :{Bitir} {Kırmızı}{j['threat']}{Bitir}")
        if j.get("tags"):
            print(f"  {Beyaz}Tag'ler      :{Bitir} {Cyan}{', '.join(j['tags'][:5])}{Bitir}")
        if j.get("date_added"):
            print(f"  {Beyaz}Eklenme      :{Bitir} {Yeşil}{j['date_added']}{Bitir}")
    else:
        print(f"  {Mor}[i]{Bitir} URLhaus: {qs}")


# ===== URLSCAN =====

def _urlscan(url):
    print(f"\n{Sarı}[*]{Bitir} urlscan.io (önceki taramalar)...")
    p = registry.get("urlscan")
    if p is None or not getattr(p, "enabled", True):
        print(f"  {Mor}[i]{Bitir} urlscan provider kapalı.")
        return
    try:
        j = p.query(f'page.url:"{url}"', size=5)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} urlscan: {e}")
        return

    results = j.get("results") or []
    if not results:
        print(f"  {Mor}[i]{Bitir} Bu URL urlscan.io'da taranmamış.")
        return

    print(f"  {Beyaz}Taramalar    :{Bitir} {Yeşil}{len(results)}{Bitir}")
    for res in results[:5]:
        page = res.get("page") or {}
        task = res.get("task") or {}
        verdict = (res.get("verdicts") or {}).get("overall") or {}
        malicious = verdict.get("malicious", False)
        score = verdict.get("score", 0)
        color = Kırmızı if malicious else Yeşil
        print(f"  {color}●{Bitir} {Cyan}{page.get('url', '?')[:80]}{Bitir}")
        print(f"     {Mor}skor: {score}  malicious: {malicious}  "
              f"tarih: {task.get('time', '?')[:10]}{Bitir}")


# ===== CORRELATION =====

def _correlate(url, host):
    try:
        db.add_entity("url", url, source="url_module", confidence="VERIFIED")
        if host:
            db.add_entity("domain", host, source="url_module", confidence="VERIFIED")
            db.add_relation(url, host, "hosted_on", evidence="URL host")
    except Exception:
        pass

    try:
        rels = db.get_relations(limit=500)
        matched = [r for r in rels if r[0] == url or r[1] == url]
    except Exception:
        return
    if not matched:
        return

    print()
    print(f"  {Cyan}┌─[ {Yeşil}İlişkiler{ Cyan} ]─────────────────────────────────────────┐{Bitir}")
    for src, dst, kind, ev, ts in matched[:15]:
        print(f"  {Cyan}│{Bitir} {Yeşil}{src}{Bitir}  {Cyan}─[{Sarı}{kind}{Cyan}]→{Bitir}  {Yeşil}{dst}{Bitir}")
    print(f"  {Cyan}└──────────────────────────────────────────────────────────┘{Bitir}")


# ===== ANA =====

def run(url):
    print(f"\n============= {Yeşil}URL INTELLIGENCE{Bitir} =============")

    if not url:
        print(f"{Kırmızı}[✗]{Bitir} Boş URL.")
        return

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"{Sarı}[*]{Bitir} Hedef: {Beyaz}{url}{Bitir}\n")

    # 1. URL yapısı
    info = _url_parse_section(url)

    # 2. Typosquat uyarısı (varsa)
    _typosquat_section(url)

    # 3. Tracking parametreleri
    _tracking_section(url)

    # 4. Redirect + HTTP
    r = _redirect_chain(url)
    if not r:
        return

    # 5. Shortener kontrolü
    _shortener_section(url, r)

    # 6. Headers
    _headers_section(r)

    # 7. CSP parse
    _csp_parse(r)

    # 8. Cookies
    _cookies_analysis(r)

    # 9. TLS
    if r.url.startswith("https://"):
        host = urlparse(r.url).hostname
        if host:
            _tls_info(host)

    # 10. Favicon
    _favicon(r)

    # 11. HTTP metodları
    _http_methods(r)

    # 12. Wayback
    _wayback(url)

    # 13. URLhaus
    _urlhaus_url(url)

    # 14. urlscan
    _urlscan(url)

    # 15. Correlation
    _correlate(url, info.get("host"))