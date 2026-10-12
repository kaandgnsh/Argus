#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Domain intelligence — DNS, RDAP, CT, HTTP/TLS, security posture."""

import hashlib
import os
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core.http import safe_get
from core import database as db
from providers import registry


RTYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]


NS_PROVIDERS = [
    ("cloudflare.com", "Cloudflare"),
    ("awsdns", "AWS Route 53"),
    ("azure-dns", "Azure DNS"),
    ("googledomains.com", "Google Domains"),
    ("google.com", "Google Cloud DNS"),
    ("nsone.net", "NS1"),
    ("digitalocean.com", "DigitalOcean"),
    ("linode.com", "Linode"),
    ("gandi.net", "Gandi"),
    ("namecheap.com", "Namecheap"),
    ("godaddy.com", "GoDaddy"),
    ("dnspod", "DNSPod"),
    ("yandex", "Yandex DNS"),
    ("vercel-dns.com", "Vercel"),
    ("netlify.com", "Netlify"),
    ("hostinger", "Hostinger"),
    ("isimtescil", "İsimtescil (TR)"),
    ("natro", "Natro (TR)"),
    ("turhost", "Turhost (TR)"),
]


TAKEOVER_FINGERPRINTS = [
    ("github.io",               "there isn't a github pages site here"),
    ("herokuapp.com",           "no such app"),
    ("herokudns.com",           "no such app"),
    ("s3.amazonaws.com",        "nosuchbucket"),
    ("cloudfront.net",          "bad request"),
    ("azurewebsites.net",       "404 web site not found"),
    ("azureedge.net",           "the requested content does not exist"),
    ("fastly.net",              "fastly error: unknown domain"),
    ("netlify.app",             "not found - request id"),
    ("netlify.com",             "not found - request id"),
    ("vercel.app",              "the deployment could not be found"),
    ("surge.sh",                "project not found"),
    ("bitbucket.io",            "repository not found"),
    ("ghost.io",                "domain error"),
    ("readme.io",               "project doesnt exist"),
    ("readme.io",               "project doesn't exist"),
    ("tumblr.com",              "there's nothing here"),
    ("pantheonsite.io",         "the gods are wise"),
    ("wpengine.com",            "we couldn't find"),
    ("statuspage.io",           "page not found"),
    ("zendesk.com",             "help center closed"),
    ("myshopify.com",           "sorry, this shop is currently unavailable"),
    ("cargo.site",              "404 not found"),
    ("fly.dev",                 "404 not found"),
]


# ===== YARDIMCILAR =====

def _dns(domain, rtype):
    for name in ("cloudflare_dns", "google_dns"):
        p = registry.get(name)
        if p is None or not getattr(p, "enabled", True):
            continue
        try:
            return p.query(domain, rtype)
        except Exception:
            continue
    return []


def _clean_txt(value):
    s = str(value).strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1]
    return s.strip()


def _strip_dot(s):
    return str(s).rstrip(".").strip()


# ===== DNS =====

def _dns_section(domain):
    print(f"{Sarı}[*]{Bitir} DNS kayıtları...")
    for rt in RTYPES:
        vals = _dns(domain, rt)
        if not vals:
            continue

        if rt == "TXT":
            cleaned = [_clean_txt(v) for v in vals]
        elif rt in ("NS", "MX", "CNAME", "SOA"):
            cleaned = [_strip_dot(v) for v in vals]
        else:
            cleaned = [str(v) for v in vals]

        joined = "; ".join(cleaned[:4])
        if len(cleaned) > 4:
            joined += f" (+{len(cleaned) - 4})"

        if rt == "TXT" and len(joined) > 140:
            joined = joined[:137] + "..."

        print(f"  {Beyaz}{rt:<6}{Bitir}: {Yeşil}{joined}{Bitir}")


# ===== NS SAĞLAYICI =====

def _ns_provider(nameservers):
    providers = set()
    for ns in nameservers:
        ns_l = str(ns).lower()
        for suffix, name in NS_PROVIDERS:
            if suffix in ns_l:
                providers.add(name)
                break
    return sorted(providers)


# ===== EMAIL SECURITY =====

def _email_security(domain):
    print(f"\n{Sarı}[*]{Bitir} Email güvenlik yapılandırması (SPF/DMARC/DKIM)...")

    spf = None
    for t in _dns(domain, "TXT") or []:
        s = _clean_txt(t)
        if "v=spf1" in s.lower():
            spf = s
            break
    if spf:
        policy = "?"
        if "-all" in spf.lower():
            policy = "strict (fail)"
        elif "~all" in spf.lower():
            policy = "soft (softfail)"
        elif "?all" in spf.lower():
            policy = "neutral"
        elif "+all" in spf.lower():
            policy = "HİÇBİR KORUMA YOK (pass all)"
        print(f"  {Beyaz}SPF          :{Bitir} {Yeşil}{spf[:100]}{Bitir}")
        print(f"  {Beyaz}SPF Policy   :{Bitir} {Yeşil}{policy}{Bitir}")
    else:
        print(f"  {Beyaz}SPF          :{Bitir} {Kırmızı}yok (email spoofing'e açık){Bitir}")

    dmarc = None
    for t in _dns(f"_dmarc.{domain}", "TXT") or []:
        s = _clean_txt(t)
        if "v=dmarc1" in s.lower():
            dmarc = s
            break
    if dmarc:
        policy_match = re.search(r"p=([a-z]+)", dmarc, re.I)
        policy = policy_match.group(1) if policy_match else "?"
        color = Yeşil
        if policy.lower() in ("none", "quarantine"):
            color = Sarı
        print(f"  {Beyaz}DMARC        :{Bitir} {Yeşil}{dmarc[:100]}{Bitir}")
        print(f"  {Beyaz}DMARC Policy :{Bitir} {color}{policy}{Bitir}")
    else:
        print(f"  {Beyaz}DMARC        :{Bitir} {Kırmızı}yok (email spoofing'e açık){Bitir}")

    dkim_found = []
    for selector in ("default", "google", "selector1", "selector2", "mail",
                     "dkim", "s1", "s2", "k1"):
        records = _dns(f"{selector}._domainkey.{domain}", "TXT") or []
        for t in records:
            s = _clean_txt(t)
            if "v=dkim1" in s.lower() or "k=rsa" in s.lower() or "p=" in s.lower():
                dkim_found.append(selector)
                break
    if dkim_found:
        print(f"  {Beyaz}DKIM         :{Bitir} {Yeşil}bulundu ({', '.join(dkim_found)}){Bitir}")
    else:
        print(f"  {Beyaz}DKIM         :{Bitir} {Mor}yaygın selector'larda yok{Bitir}")


# ===== RDAP =====

def _rdap(domain):
    print(f"\n{Sarı}[*]{Bitir} RDAP (WHOIS alternatifi)...")
    p = registry.get("rdap")
    if p is None or not getattr(p, "enabled", True):
        print(f"  {Mor}[!]{Bitir} RDAP provider kapalı.")
        return
    try:
        data = p.query(domain)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} RDAP: {e}")
        return

    for ev in (data.get("events") or [])[:6]:
        print(f"  {Beyaz}{ev.get('eventAction', '?'):<15}{Bitir}: "
              f"{Yeşil}{ev.get('eventDate', '?')}{Bitir}")

    for ent in (data.get("entities") or [])[:6]:
        roles = ",".join(ent.get("roles", []))
        vcard = ent.get("vcardArray") or []
        name = ent.get("handle", "?")
        try:
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        name = item[3]
                        break
        except Exception:
            pass
        print(f"  {Beyaz}Entity ({roles}){Bitir}: {Cyan}{name}{Bitir}")

    status = data.get("status") or []
    if status:
        print(f"  {Beyaz}Status       :{Bitir} {Yeşil}{', '.join(status)}{Bitir}")


# ===== SUBDOMAIN (crt.sh) =====

def _write_subdomains_to_files(domain, subs, user_log_path=None):
    """Subdomain listesini farklı yerlere yazar. Yazılan yolları döner."""
    written = []
    now = datetime.now()
    ts = now.strftime("%Y%m%d_%H%M%S")
    header = (
        f"# Subdomains for {domain}\n"
        f"# Count: {len(subs)}\n"
        f"# Source: crt.sh (Certificate Transparency)\n"
        f"# Date: {now.isoformat(timespec='seconds')}\n"
        + "# " + "=" * 60 + "\n"
    )

    # 1. reports/subdomains_<domain>_<ts>.txt — timestamp'li snapshot
    try:
        os.makedirs("reports", exist_ok=True)
        safe_domain = re.sub(r"[^A-Za-z0-9._\-]", "_", domain)
        path = os.path.join("reports", f"subdomains_{safe_domain}_{ts}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(header + "\n")
            for s in subs:
                f.write(s + "\n")
        written.append(path)
    except OSError:
        pass

    # 2. logs/subdomains.log — kümülatif append (her sorgu eklenir)
    try:
        os.makedirs("logs", exist_ok=True)
        path = os.path.join("logs", "subdomains.log")
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n" + header + "\n")
            for s in subs:
                f.write(s + "\n")
        written.append(path)
    except OSError:
        pass

    # 3. Kullanıcının verdiği özel log dosyası (opsiyonel)
    if user_log_path:
        try:
            parent = os.path.dirname(user_log_path) or "."
            os.makedirs(parent, exist_ok=True)
            with open(user_log_path, "a", encoding="utf-8") as f:
                f.write("\n" + header + "\n")
                for s in subs:
                    f.write(s + "\n")
            written.append(user_log_path)
        except OSError:
            pass

    return written


def _subdomains(domain, user_log_path=None):
    print(f"\n{Sarı}[*]{Bitir} Certificate Transparency (crt.sh)...")
    p = registry.get("crtsh")
    if p is None or not getattr(p, "enabled", True):
        print(f"  {Mor}[!]{Bitir} crt.sh provider kapalı.")
        return []
    try:
        subs = p.query(domain)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} crt.sh: {e}")
        return []

    if not subs:
        print(f"  {Mor}[i]{Bitir} Subdomain bulunamadı.")
        return []

    print(f"  {Beyaz}Toplam      :{Bitir} {Yeşil}{len(subs)} subdomain{Bitir}")
    for s in subs[:20]:
        print(f"  {Cyan}{s}{Bitir}")
    if len(subs) > 20:
        print(f"  {Mor}... +{len(subs) - 20} daha (tam liste dosyalara kaydedildi){Bitir}")

    # Dosyalara yaz
    written = _write_subdomains_to_files(domain, subs, user_log_path)
    for p in written:
        print(f"  {Yeşil}[✓]{Bitir} Tam liste: {Cyan}{p}{Bitir}")

    return subs


# ===== HTTP HEADERS =====

def _http_headers(domain):
    print(f"\n{Sarı}[*]{Bitir} HTTP headers + güvenlik header'ları...")
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = safe_get(url, timeout=8, allow_redirects=True)
        except Exception:
            continue

        print(f"  {Beyaz}Final URL    :{Bitir} {Yeşil}{r.url}{Bitir}")
        print(f"  {Beyaz}Status       :{Bitir} {Yeşil}{r.status_code}{Bitir}")

        important = [
            "Server", "X-Powered-By", "Content-Type",
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy",
            "CF-Ray", "X-Vercel-Id", "X-Amz-Cf-Id",
        ]
        for h in important:
            v = r.headers.get(h)
            if v:
                val = v[:80] + ("..." if len(v) > 80 else "")
                print(f"  {Beyaz}{h:<28}:{Bitir} {Yeşil}{val}{Bitir}")

        missing = []
        for h in ("Strict-Transport-Security", "Content-Security-Policy",
                  "X-Frame-Options", "X-Content-Type-Options"):
            if not r.headers.get(h):
                missing.append(h)
        if missing:
            print(f"  {Sarı}⚠  Eksik güvenlik header'ları: {', '.join(missing)}{Bitir}")
        return
    print(f"  {Mor}[!]{Bitir} HTTP/HTTPS erişilemedi.")


# ===== TLS =====

def _tls_info(domain):
    print(f"\n{Sarı}[*]{Bitir} TLS sertifika bilgisi...")

    version = None
    cipher = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} TLS bağlantı hatası: {e}")
        return

    if version:
        print(f"  {Beyaz}TLS Version  :{Bitir} {Yeşil}{version}{Bitir}")
    if cipher:
        print(f"  {Beyaz}Cipher       :{Bitir} {Yeşil}{cipher[0]}{Bitir}")

    cert = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError:
        pass
    except Exception:
        pass

    if not cert:
        # Fallback: DER -> PEM -> Python decoder
        try:
            import base64
            import tempfile
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    der = ssock.getpeercert(binary_form=True)
            if der:
                pem = ("-----BEGIN CERTIFICATE-----\n"
                       + base64.encodebytes(der).decode("ascii")
                       + "-----END CERTIFICATE-----\n")
                with tempfile.NamedTemporaryFile("w", delete=False,
                                                 suffix=".pem") as f:
                    f.write(pem)
                    tmp = f.name
                try:
                    cert = ssl._ssl._test_decode_cert(tmp)
                finally:
                    os.unlink(tmp)
        except Exception:
            cert = None

    if not cert:
        print(f"  {Mor}[i]{Bitir} Sertifika detayı alınamadı.")
        return

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    print(f"  {Beyaz}Subject CN   :{Bitir} {Yeşil}{subject.get('commonName', '?')}{Bitir}")
    print(f"  {Beyaz}Subject O    :{Bitir} {Yeşil}{subject.get('organizationName', '-')}{Bitir}")
    print(f"  {Beyaz}Issuer CN    :{Bitir} {Yeşil}{issuer.get('commonName', '?')}{Bitir}")
    print(f"  {Beyaz}Issuer O     :{Bitir} {Yeşil}{issuer.get('organizationName', '-')}{Bitir}")
    print(f"  {Beyaz}Valid From   :{Bitir} {Yeşil}{cert.get('notBefore', '?')}{Bitir}")
    print(f"  {Beyaz}Valid Until  :{Bitir} {Yeşil}{cert.get('notAfter', '?')}{Bitir}")

    san = cert.get("subjectAltName") or []
    if san:
        dns_names = [v for (k, v) in san if k == "DNS"]
        if dns_names:
            preview = ", ".join(dns_names[:8])
            extra = f" (+{len(dns_names) - 8})" if len(dns_names) > 8 else ""
            print(f"  {Beyaz}SAN          :{Bitir} {Cyan}{preview}{extra}{Bitir}")


# ===== ROBOTS.TXT =====

def _robots(domain):
    print(f"\n{Sarı}[*]{Bitir} robots.txt...")
    try:
        r = safe_get(f"https://{domain}/robots.txt", timeout=6)
        if r.status_code != 200:
            print(f"  {Mor}[i]{Bitir} robots.txt yok (HTTP {r.status_code})")
            return
        text = r.text[:3000]
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        disallow = [l for l in lines if l.lower().startswith("disallow")][:10]
        sitemaps = [l for l in lines if l.lower().startswith("sitemap")][:5]
        if disallow:
            print(f"  {Beyaz}Disallow{'' : <4}:{Bitir}")
            for d in disallow:
                print(f"    {Cyan}{d}{Bitir}")
        if sitemaps:
            print(f"  {Beyaz}Sitemap{'' : <5}:{Bitir}")
            for s in sitemaps:
                print(f"    {Cyan}{s}{Bitir}")
        if not disallow and not sitemaps:
            print(f"  {Mor}[i]{Bitir} robots.txt mevcut ama ilginç kural yok.")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} robots.txt: {e}")


# ===== SITEMAP =====

def _sitemap(domain):
    print(f"\n{Sarı}[*]{Bitir} sitemap.xml...")
    for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"):
        try:
            r = safe_get(f"https://{domain}{path}", timeout=6)
            if r.status_code == 200 and ("<urlset" in r.text or "<sitemapindex" in r.text):
                urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text)
                print(f"  {Beyaz}Bulundu      :{Bitir} {Yeşil}{path} ({len(urls)} URL){Bitir}")
                for u in urls[:8]:
                    print(f"    {Cyan}{u[:80]}{Bitir}")
                if len(urls) > 8:
                    print(f"    {Mor}... +{len(urls) - 8} daha{Bitir}")
                return
        except Exception:
            continue
    print(f"  {Mor}[i]{Bitir} sitemap.xml bulunamadı.")


# ===== SECURITY.TXT =====

def _security_txt(domain):
    print(f"\n{Sarı}[*]{Bitir} security.txt...")
    paths = ["/.well-known/security.txt", "/security.txt"]
    for path in paths:
        try:
            r = safe_get(f"https://{domain}{path}", timeout=6)
            if r.status_code == 200 and "contact:" in r.text.lower():
                print(f"  {Beyaz}Bulundu      :{Bitir} {Yeşil}{path}{Bitir}")
                for line in r.text.splitlines()[:12]:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        print(f"    {Cyan}{line[:100]}{Bitir}")
                return
        except Exception:
            continue
    print(f"  {Mor}[i]{Bitir} security.txt yok.")


# ===== FAVICON HASH =====

def _favicon(domain):
    print(f"\n{Sarı}[*]{Bitir} Favicon hash (Shodan-style SHA256)...")
    for path in ("/favicon.ico", "/favicon.png"):
        try:
            r = safe_get(f"https://{domain}{path}", timeout=6)
            if r.status_code == 200 and len(r.content) > 0:
                h = hashlib.sha256(r.content).hexdigest()
                print(f"  {Beyaz}Path         :{Bitir} {Yeşil}{path}{Bitir}")
                print(f"  {Beyaz}Size         :{Bitir} {Yeşil}{len(r.content)} B{Bitir}")
                print(f"  {Beyaz}SHA256       :{Bitir} {Cyan}{h}{Bitir}")
                return
        except Exception:
            continue
    print(f"  {Mor}[i]{Bitir} Favicon alınamadı.")


# ===== NS SAĞLAYICI =====

def _ns_section(nameservers):
    if not nameservers:
        return
    providers = _ns_provider(nameservers)
    if providers:
        print(f"  {Beyaz}NS Sağlayıcı:{Bitir} {Yeşil}{', '.join(providers)}{Bitir}")


# ===== ZONE TRANSFER (AXFR) =====

def _zone_transfer(domain, nameservers):
    print(f"\n{Sarı}[*]{Bitir} DNS zone transfer (AXFR) denemesi...")

    try:
        import dns.query
        import dns.zone
    except ImportError:
        print(f"  {Mor}[!]{Bitir} dnspython kurulu değil.")
        return

    ns_ips = []
    for ns in nameservers[:3]:
        ns_clean = _strip_dot(ns)
        ips = _dns(ns_clean, "A") or []
        for ip in ips[:2]:
            ns_ips.append((ns_clean, str(ip)))

    if not ns_ips:
        print(f"  {Mor}[i]{Bitir} NS IP'si çözülemedi (DoH cevap vermedi).")
        return

    success = False
    for ns_name, ns_ip in ns_ips:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=8))
            names = list(zone.nodes.keys())
            print(f"  {Kırmızı}⚠ ZONE TRANSFER BAŞARILI — {ns_name} ({ns_ip}){Bitir}")
            print(f"  {Kırmızı}  {len(names)} kayıt açığa çıktı — ciddi yapılandırma hatası!{Bitir}")
            for n in names[:10]:
                print(f"    {Cyan}{n}{Bitir}")
            success = True
            break
        except Exception:
            continue

    if not success:
        print(f"  {Yeşil}[✓]{Bitir} Zone transfer reddedildi (normal davranış).")


# ===== SUBDOMAIN TAKEOVER =====

def _takeover_check(subdomains):
    if not subdomains:
        return
    print(f"\n{Sarı}[*]{Bitir} Subdomain takeover kontrolü (ilk 20 subdomain)...")

    found = 0
    for sub in subdomains[:20]:
        cnames = _dns(sub, "CNAME") or []
        if not cnames:
            continue
        cname = _strip_dot(cnames[0]).lower()

        for suffix, marker in TAKEOVER_FINGERPRINTS:
            if suffix in cname:
                try:
                    r = safe_get(f"https://{sub}", timeout=6, allow_redirects=True)
                    body = r.text[:30_000].lower()
                    if marker and marker in body:
                        print(f"  {Kırmızı}⚠ TAKEOVER ADAYI: {sub}{Bitir}")
                        print(f"     {Beyaz}CNAME: {Cyan}{cname}{Bitir}")
                        print(f"     {Beyaz}Marker: {Mor}{marker[:60]}{Bitir}")
                        found += 1
                except Exception:
                    pass
                break

    if found == 0:
        print(f"  {Yeşil}[✓]{Bitir} Şüpheli subdomain takeover bulgusu yok.")


# ===== CORRELATION =====

def _correlate(domain, info):
    try:
        db.add_entity("domain", domain, data=info, source="domain_module",
                      confidence="VERIFIED")
        for ip in info.get("a_records", [])[:5]:
            ip_s = str(ip)
            db.add_entity("ip", ip_s, source="domain_dns", confidence="VERIFIED")
            db.add_relation(domain, ip_s, "resolves_to", evidence="DNS A")
        for ns in info.get("nameservers", [])[:5]:
            ns_s = _strip_dot(ns)
            db.add_entity("nameserver", ns_s, source="domain_dns", confidence="VERIFIED")
            db.add_relation(domain, ns_s, "uses_nameserver", evidence="DNS NS")
        for mx in info.get("mx_records", [])[:5]:
            mx_s = _strip_dot(mx)
            mx_s = re.sub(r"^\d+\s+", "", mx_s)
            db.add_relation(domain, mx_s, "mail_exchange", evidence="DNS MX")

        # Subdomain'lerin TAMAMINI DB'ye kaydet
        for sub in info.get("subdomains", []):
            sub_s = _strip_dot(sub)
            if not sub_s or sub_s == domain:
                continue
            db.add_entity("subdomain", sub_s, source="crtsh", confidence="VERIFIED")
            db.add_relation(domain, sub_s, "has_subdomain", evidence="crt.sh")
    except Exception:
        pass

    try:
        rels = db.get_relations(limit=2000)
        matched = [r for r in rels if r[0] == domain or r[1] == domain]
    except Exception:
        return
    if not matched:
        return

    print()
    print(f"  {Cyan}┌─[ {Yeşil}İlişkiler{ Cyan} ]─────────────────────────────────────────┐{Bitir}")

    shown = 0
    subdomain_count = 0
    for src, dst, kind, ev, ts in matched:
        if kind == "has_subdomain":
            subdomain_count += 1
            continue
        if shown >= 15:
            continue
        print(f"  {Cyan}│{Bitir} {Yeşil}{src}{Bitir}  {Cyan}─[{Sarı}{kind}{Cyan}]→{Bitir}  {Yeşil}{dst}{Bitir}")
        shown += 1

    if subdomain_count:
        print(f"  {Cyan}│{Bitir} {Mor}... {subdomain_count} subdomain ilişkisi DB'ye kaydedildi{Bitir}")

    print(f"  {Cyan}└──────────────────────────────────────────────────────────┘{Bitir}")


# ===== ANA =====

def run(domain, subdomain_log=None):
    print(f"\n============= {Yeşil}DOMAIN INTELLIGENCE{Bitir} =============")

    if not domain:
        print(f"{Kırmızı}[✗]{Bitir} Boş domain.")
        return

    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc or domain
    domain = domain.rstrip("/")

    print(f"{Sarı}[*]{Bitir} Hedef: {Beyaz}{domain}{Bitir}\n")

    info = {}

    _dns_section(domain)
    a_records = _dns(domain, "A") or []
    mx_records = _dns(domain, "MX") or []
    nameservers = _dns(domain, "NS") or []
    info["a_records"] = a_records
    info["mx_records"] = mx_records
    info["nameservers"] = nameservers

    _ns_section(nameservers)
    _email_security(domain)
    _rdap(domain)

    subs = _subdomains(domain, user_log_path=subdomain_log)
    info["subdomains"] = subs

    _http_headers(domain)
    _tls_info(domain)
    _robots(domain)
    _sitemap(domain)
    _security_txt(domain)
    _favicon(domain)

    if nameservers:
        _zone_transfer(domain, nameservers)

    if subs:
        _takeover_check(subs)

    _correlate(domain, info)