#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Email intelligence — keyless multi-check."""

import hashlib
import re

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core.http import safe_get
from core import database as db
from providers import registry
from modules import search as search_provider


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


COMMON_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "yahoo.com", "yahoo.co.uk", "icloud.com", "me.com",
    "protonmail.com", "proton.me", "yandex.com", "yandex.ru",
    "mail.ru", "gmx.com", "gmx.de", "aol.com", "zoho.com",
    "fastmail.com", "tutanota.com", "hey.com",
}

ROLE_LOCALS = {
    "admin", "administrator", "info", "support", "help", "contact",
    "sales", "marketing", "billing", "office", "hello", "team",
    "noreply", "no-reply", "postmaster", "webmaster", "hostmaster",
    "abuse", "security", "privacy", "legal", "hr", "jobs", "careers",
    "press", "media", "news", "feedback", "root", "mail", "email",
}


def validate(email):
    if not email or not EMAIL_RE.match(email):
        return False, "syntax invalid"
    return True, "ok"


def normalize(email):
    return email.strip().lower()


# ===== TYPO DETECTION =====

def _levenshtein(a, b, max_d=3):
    if abs(len(a) - len(b)) > max_d:
        return max_d + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def _typo_suggestion(domain):
    domain = domain.lower()
    if domain in COMMON_DOMAINS:
        return None
    best = None
    best_d = 99
    for d in COMMON_DOMAINS:
        dist = _levenshtein(domain, d, max_d=2)
        if dist < best_d and dist <= 2:
            best_d = dist
            best = d
    return best


# ===== DNS =====

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
    """DNS TXT kayıtlarını temizler: baş/son tırnak ve boşlukları atar.

    Örnek:
      '"v=spf1 redirect=_spf.google.com"'  ->  'v=spf1 redirect=_spf.google.com'
      'v=DMARC1; p=none'                    ->  'v=DMARC1; p=none'
    """
    s = str(value).strip()
    # DNS sağlayıcıları bazen tırnaklı döner
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1]
    return s.strip()


def _spf_dmarc(domain):
    spf = None
    dmarc = None

    txts = _dns(domain, "TXT") or []
    for t in txts:
        s = _clean_txt(t)
        if "v=spf1" in s.lower():
            spf = s
            break

    dmarc_records = _dns(f"_dmarc.{domain}", "TXT") or []
    for t in dmarc_records:
        s = _clean_txt(t)
        if "v=dmarc1" in s.lower():
            dmarc = s
            break

    return spf, dmarc


# ===== GRAVATAR =====

def _gravatar(email):
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/avatar/{h}?d=404"
    try:
        r = safe_get(url, timeout=6)
        if r.status_code == 200:
            return f"https://www.gravatar.com/avatar/{h}"
    except Exception:
        pass
    return None


# ===== GITHUB =====

def _github(email):
    try:
        r = safe_get(
            "https://api.github.com/search/users",
            params={"q": f"{email} in:email"},
            timeout=10,
        )
        if r.status_code == 200:
            items = r.json().get("items") or []
            return [i.get("login") for i in items[:5]]
    except Exception:
        pass
    return []


# ===== DORK =====

def _search_one(query, max_results=2):
    results = search_provider.search(query, max_results=max_results)
    if results:
        return results, "ddg"
    bing = registry.get("bing_search")
    if bing and getattr(bing, "enabled", True):
        try:
            return bing.query(query, max_results=max_results), "bing"
        except Exception:
            pass
    return [], None


def _dork(email):
    targets = {
        "Pastebin": f'site:pastebin.com "{email}"',
        "GitHub":   f'site:github.com "{email}"',
        "GitLab":   f'site:gitlab.com "{email}"',
    }
    hits = 0
    for platform, q in targets.items():
        results, src = _search_one(q, max_results=2)
        if results:
            for url in results:
                print(f"  {Beyaz}[ {Yeşil}FOUND {Beyaz}]{Bitir} {platform:<10} "
                      f"{Cyan}{url}{Bitir} {Mor}({src}){Bitir}")
                hits += 1
    if hits == 0:
        print(f"  {Mor}[i]{Bitir} Public dork sonucu yok.")


# ===== USERNAME CANDIDATES =====

def _username_candidates(local):
    local = local.lower()
    candidates = {local}
    for sep in ("", ".", "_", "-"):
        candidates.add(re.sub(r"[._\-]", sep, local))
    if "." in local:
        parts = local.split(".")
        candidates.add(parts[0])
        if len(parts) >= 2:
            candidates.add(parts[0] + parts[1])
    stripped = re.sub(r"\d+$", "", local)
    if stripped != local:
        candidates.add(stripped)
    return sorted(c for c in candidates if 2 <= len(c) <= 32)


# ===== CORRELATION =====

def _correlate(email, domain, candidates):
    try:
        db.add_entity("email", email, source="email_module", confidence="VERIFIED")
        if domain:
            db.add_entity("domain", domain, source="email_module", confidence="VERIFIED")
            db.add_relation(email, domain, "belongs_to_domain",
                            evidence="email address")
        for c in candidates[:5]:
            db.add_entity("username", c, source="email_derived", confidence="GUESS")
            db.add_relation(email, c, "username_candidate",
                            evidence="derived from local-part")
    except Exception:
        pass

    try:
        rels = db.get_relations(limit=500)
        matched = [r for r in rels if r[0] == email or r[1] == email]
    except Exception:
        return
    if not matched:
        return

    print()
    print(f"  {Cyan}┌─[ {Yeşil}İlişkiler{ Cyan} ]─────────────────────────────────────────┐{Bitir}")
    for src, dst, kind, ev, ts in matched[:15]:
        print(f"  {Cyan}│{Bitir} {Yeşil}{src}{Bitir}  {Cyan}─[{Sarı}{kind}{Cyan}]→{Bitir}  {Yeşil}{dst}{Bitir}")
    if len(matched) > 15:
        print(f"  {Cyan}│{Bitir} {Mor}... +{len(matched) - 15} daha{Bitir}")
    print(f"  {Cyan}└──────────────────────────────────────────────────────────┘{Bitir}")


# ===== ANA =====

def run(email):
    print(f"\n============= {Yeşil}EMAIL INTELLIGENCE{Bitir} =============")

    if not email:
        print(f"{Kırmızı}[✗]{Bitir} Boş email.")
        return

    email = normalize(email)
    ok, reason = validate(email)
    if not ok:
        print(f"{Kırmızı}[✗]{Bitir} {reason}: {email}")
        return

    print(f"{Sarı}[*]{Bitir} Hedef: {Beyaz}{email}{Bitir}\n")
    local, domain = email.split("@", 1)

    print(f"  {Beyaz}Local        :{Bitir} {Yeşil}{local}{Bitir}")
    print(f"  {Beyaz}Domain       :{Bitir} {Yeşil}{domain}{Bitir}")
    print(f"  {Beyaz}MD5          :{Bitir} {Cyan}{hashlib.md5(email.encode()).hexdigest()}{Bitir}")
    print(f"  {Beyaz}SHA256       :{Bitir} {Cyan}{hashlib.sha256(email.encode()).hexdigest()}{Bitir}")

    # Typo
    typo = _typo_suggestion(domain)
    if typo:
        print(f"  {Sarı}⚠  Typo olabilir:{Bitir} {Cyan}{domain}{Bitir} → belki {Yeşil}{typo}{Bitir}?")

    # Disposable
    p = registry.get("disposable_email")
    if p and getattr(p, "enabled", True):
        try:
            j = p.query(email)
            if j.get("disposable"):
                print(f"  {Beyaz}Disposable   :{Bitir} {Kırmızı}EVET (tek kullanımlık email servisi){Bitir}")
            else:
                print(f"  {Beyaz}Disposable   :{Bitir} {Yeşil}hayır{Bitir}")
        except Exception as e:
            print(f"  {Mor}[!]{Bitir} Disposable check: {e}")
    else:
        print(f"  {Mor}[i]{Bitir} disposable_email provider kapalı veya kayıtlı değil.")

    # Role-based
    if local in ROLE_LOCALS:
        print(f"  {Beyaz}Role-based   :{Bitir} {Sarı}EVET ({local}@ tipik rol adresi){Bitir}")

    # MX
    mx = _dns(domain, "MX") or []
    if mx:
        print(f"\n{Sarı}[*]{Bitir} MX kayıtları:")
        for r in mx[:5]:
            print(f"  {Yeşil}{r}{Bitir}")
    else:
        print(f"\n{Mor}[!]{Bitir} MX yok — domain email kabul etmiyor olabilir.")

    # SPF / DMARC
    spf, dmarc = _spf_dmarc(domain)
    print(f"\n{Sarı}[*]{Bitir} Email authentication...")
    if spf:
        print(f"  {Beyaz}SPF          :{Bitir} {Yeşil}{spf[:80]}{Bitir}")
    else:
        print(f"  {Beyaz}SPF          :{Bitir} {Mor}yok{Bitir}")
    if dmarc:
        print(f"  {Beyaz}DMARC        :{Bitir} {Yeşil}{dmarc[:80]}{Bitir}")
    else:
        print(f"  {Beyaz}DMARC        :{Bitir} {Mor}yok{Bitir}")

    # Gravatar
    print(f"\n{Sarı}[*]{Bitir} Gravatar...")
    g = _gravatar(email)
    if g:
        print(f"  {Yeşil}[FOUND]{Bitir} {g}")
    else:
        print(f"  {Mor}[ NOT FOUND ]{Bitir}")

    # GitHub
    print(f"\n{Sarı}[*]{Bitir} GitHub correlation...")
    gh = _github(email)
    if gh:
        for u in gh:
            print(f"  {Yeşil}[FOUND]{Bitir} https://github.com/{u}")
    else:
        print(f"  {Mor}[ UNKNOWN ]{Bitir}")

    # Username candidates
    candidates = _username_candidates(local)
    print(f"\n{Sarı}[*]{Bitir} Kullanıcı adı adayları (email local-part'tan):")
    for c in candidates[:8]:
        print(f"  {Cyan}{c}{Bitir}")

    # Dork
    print(f"\n{Sarı}[*]{Bitir} Dork taraması...")
    _dork(email)

    # Correlation
    _correlate(email, domain, candidates)