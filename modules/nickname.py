#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Deep Nick Search — multi-platform, confidence-scored, correlation-aware."""

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from bs4 import BeautifulSoup

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core.config import CONFIG
from core.http import _session as _http_session
from core import database as db


PLATFORMS = [
    {"name": "GitHub",        "url": "https://github.com/{u}"},
    {"name": "GitLab",        "url": "https://gitlab.com/{u}"},
    {"name": "Codeberg",      "url": "https://codeberg.org/{u}"},
    {"name": "Dev.to",        "url": "https://dev.to/{u}"},
    {"name": "Hashnode",      "url": "https://hashnode.com/@{u}"},
    {"name": "Replit",        "url": "https://replit.com/@{u}"},
    {"name": "PyPI",          "url": "https://pypi.org/user/{u}/"},
    {"name": "npm",           "url": "https://www.npmjs.com/~{u}"},
    {"name": "Docker Hub",    "url": "https://hub.docker.com/u/{u}"},
    {"name": "HuggingFace",   "url": "https://huggingface.co/{u}"},
    {"name": "Kaggle",        "url": "https://www.kaggle.com/{u}"},
    {"name": "Reddit",        "url": "https://www.reddit.com/user/{u}"},
    {"name": "Instagram",     "url": "https://www.instagram.com/{u}/"},
    {"name": "TikTok",        "url": "https://www.tiktok.com/@{u}"},
    {"name": "YouTube",       "url": "https://www.youtube.com/@{u}"},
    {"name": "Pinterest",     "url": "https://www.pinterest.com/{u}/"},
    {"name": "Telegram",      "url": "https://t.me/{u}"},
    {"name": "Snapchat",      "url": "https://www.snapchat.com/add/{u}"},
    {"name": "Tumblr",        "url": "https://{u}.tumblr.com"},
    {"name": "Mastodon",      "url": "https://mastodon.social/@{u}"},
    {"name": "Bluesky",       "url": "https://bsky.app/profile/{u}.bsky.social"},
    {"name": "VK",            "url": "https://vk.com/{u}"},
    {"name": "SoundCloud",    "url": "https://soundcloud.com/{u}"},
    {"name": "Twitch",        "url": "https://www.twitch.tv/{u}"},
    {"name": "Medium",        "url": "https://medium.com/@{u}"},
    {"name": "Substack",      "url": "https://{u}.substack.com"},
    {"name": "Flickr",        "url": "https://www.flickr.com/people/{u}"},
    {"name": "Behance",       "url": "https://www.behance.net/{u}"},
    {"name": "Dribbble",      "url": "https://dribbble.com/{u}"},
    {"name": "ArtStation",    "url": "https://www.artstation.com/{u}"},
    {"name": "Patreon",       "url": "https://www.patreon.com/{u}"},
    {"name": "Steam",         "url": "https://steamcommunity.com/id/{u}"},
    {"name": "Chess.com",     "url": "https://www.chess.com/member/{u}"},
    {"name": "Lichess",       "url": "https://lichess.org/@/{u}"},
    {"name": "Linktree",      "url": "https://linktr.ee/{u}"},
    {"name": "Keybase",       "url": "https://keybase.io/{u}"},
    {"name": "About.me",      "url": "https://about.me/{u}"},
    {"name": "Gravatar",      "url": "https://gravatar.com/{u}"},
    {"name": "WordPress",     "url": "https://{u}.wordpress.com"},
    {"name": "Blogger",       "url": "https://{u}.blogspot.com"},
    {"name": "Notion",        "url": "https://{u}.notion.site"},
    {"name": "Disqus",        "url": "https://disqus.com/by/{u}/"},
]


# Yumuşak başlık işaretleri — görülürse profil sayfası değil
_GENERIC_TITLE_MARKERS = [
    "sign in", "sign up", "log in", "login", "sign-in", "sign-up",
    "just a moment", "attention required", "client challenge",
    "checking your browser", "access denied", "forbidden",
    "are you a robot", "verify you are human",
    "page not found", "page unavailable",
]

# Spesifik nf (not-found) imzaları — sadece title/h1 üzerinde aranır.
# Body'de değil, çünkü "404" gibi kısa string'ler her yerde geçer.
_NF_PATTERNS = [
    "page not found", "page isn't available", "page not available",
    "sorry, nobody", "couldn't find this account",
    "this page isn't available", "there's nothing here",
    "user not found", "profile not found", "channel invalid",
    "if you have telegram", "we can't find that user",
    "specified profile could not be found", "doesn't exist",
    "not found", "404",
]


def _extract_meta(html):
    out = {"title": None, "og_title": None, "og_url": None, "h1": None}
    try:
        soup = BeautifulSoup(html, "html.parser")
        if soup.title and soup.title.string:
            out["title"] = soup.title.string.strip()[:200]

        for prop, key in (("og:title", "og_title"), ("og:url", "og_url")):
            el = soup.find("meta", property=prop)
            if el and el.get("content"):
                out[key] = el["content"].strip()[:300]

        h1 = soup.find("h1")
        if h1:
            out["h1"] = h1.get_text(strip=True)[:200]
    except Exception:
        pass
    return out


def _is_generic_title(title, platform_name):
    if not title:
        return True
    t = title.strip().lower()
    if len(t) < 3:
        return True

    pn = platform_name.lower()
    if t == pn or t == pn + ".com" or t == pn + " - " + pn:
        return True
    if t.strip(" -|·•.") == pn:
        return True

    for m in _GENERIC_TITLE_MARKERS:
        if m in t:
            return True
    return False


def _title_says_not_found(title):
    """Title veya h1 'not found' mesajı içeriyor mu?"""
    if not title:
        return False
    t = title.strip().lower()
    # Sadece tam "not found" cümleleri, kelime sınırıyla
    for pat in _NF_PATTERNS:
        if pat in t:
            # Kısa marker'lar için ("404", "not found") kelime sınırı kontrolü
            if len(pat) < 12:
                # Regex ile kelime sınırı ara
                if re.search(r"\b" + re.escape(pat) + r"\b", t):
                    return True
            else:
                return True
    return False


def _classify(site, username, response):
    if response is None:
        return ("ERROR", None, "no response")

    code = response.status_code
    if code == 404:
        return ("NOT FOUND", None, None)
    if code in (403, 429):
        return ("UNKNOWN", None, f"HTTP {code}")
    if code == 410:
        # Gone — kaynak kaldırılmış, muhtemelen yok
        return ("NOT FOUND", None, "HTTP 410 gone")
    if code >= 500:
        return ("UNKNOWN", None, f"HTTP {code}")
    if code != 200:
        return ("UNKNOWN", None, f"HTTP {code}")

    html = response.text
    body_l = html[:80_000].lower()

    # Cloudflare/bot challenge kontrolü (önce)
    if any(m in body_l for m in ("just a moment", "client challenge",
                                 "attention required", "checking your browser",
                                 "are you a robot")):
        return ("UNKNOWN", None, "challenge page")

    meta = _extract_meta(html)
    title = meta["title"]
    h1 = meta["h1"]
    user_l = username.lower()

    # === NOT FOUND kontrolü — SADECE title/h1 üzerinde ===
    if _title_says_not_found(title):
        return ("NOT FOUND", title, None)
    if _title_says_not_found(h1):
        return ("NOT FOUND", h1, None)

    # === FOUND: username title/og/h1'de ===
    if title and user_l in title.lower() and not _is_generic_title(title, site["name"]):
        return ("FOUND", title, None)

    if meta["og_title"] and user_l in meta["og_title"].lower():
        return ("FOUND", title or meta["og_title"], None)

    if meta["og_url"]:
        og_u = meta["og_url"].lower()
        if user_l in og_u and "/accounts/login" not in og_u:
            return ("FOUND", title or meta["og_url"], None)

    if h1 and user_l in h1.lower():
        return ("LIKELY", h1, None)

    # === LIKELY: handle pattern body'de ===
    handle_patterns = (
        f'@{user_l}"',
        f'@{user_l}<',
        f"@{user_l}'",
        f'"{user_l}":{{',
        f'"screen_name":"{user_l}"',
        f'"username":"{user_l}"',
        f'"login":"{user_l}"',
    )
    for hp in handle_patterns:
        if hp in body_l:
            return ("LIKELY", title, None)

    # === UNKNOWN ===
    if not _is_generic_title(title, site["name"]):
        return ("UNKNOWN", title, "title non-generic, username kanıtı yok")

    return ("UNKNOWN", title, "profil kanıtı yok")


def _check(site, username, timeout):
    url = site["url"].format(u=username)
    t0 = time.time()
    try:
        r = _http_session().get(url, timeout=timeout, allow_redirects=True)
    except Exception as e:
        return {
            "site": site, "url": url, "status": "ERROR",
            "title": None, "extra": str(e)[:80],
            "elapsed": time.time() - t0,
        }
    status, title, extra = _classify(site, username, r)
    return {
        "site": site, "url": url, "status": status,
        "title": title, "extra": extra,
        "elapsed": time.time() - t0,
    }


_TAG = {
    "FOUND":     f"{Yeşil}FOUND    {Bitir}",
    "LIKELY":    f"{Sarı}LIKELY   {Bitir}",
    "UNKNOWN":   f"{Mor}UNKNOWN  {Bitir}",
    "NOT FOUND": f"{Kırmızı}NOT FOUND{Bitir}",
    "ERROR":     f"{Mor}ERROR    {Bitir}",
}
_ORDER = {"FOUND": 0, "LIKELY": 1, "UNKNOWN": 2, "NOT FOUND": 3, "ERROR": 4}


def _print_result(r):
    status = r["status"]
    tag = _TAG.get(status, f"{Mor}?        {Bitir}")
    name = r["site"]["name"]

    if status in ("FOUND", "LIKELY"):
        title = f" {Cyan}({r['title']}){Bitir}" if r["title"] else ""
        print(f"  [{tag}] {name:<14} {Yeşil}{r['url']}{Bitir}{title}")
    elif status in ("UNKNOWN", "ERROR"):
        reason = f" {Mor}({r['extra']}){Bitir}" if r.get("extra") else ""
        print(f"  [{tag}] {name:<14}{reason}")
    else:
        print(f"  [{tag}] {name:<14}")


def _correlate(username, results):
    try:
        db.add_entity("username", username, source="nickname_module",
                      confidence="VERIFIED")
    except Exception:
        pass

    saved = []
    for r in results:
        if r["status"] in ("FOUND", "LIKELY"):
            platform = r["site"]["name"]
            confidence = "LIKELY" if r["status"] == "LIKELY" else "VERIFIED"
            try:
                db.add_entity("profile", r["url"],
                              data={"platform": platform, "title": r["title"]},
                              source="nickname_module", confidence=confidence)
                db.add_relation(username, r["url"], "has_profile",
                                evidence=f"{platform} — {r['status']}")
            except Exception:
                pass
            saved.append({
                "url": r["url"],
                "platform": platform,
                "status": r["status"],
            })
    return saved


def _show_relations(username, saved):
    if not saved:
        print(f"\n  {Mor}[i]{Bitir} Bu scan'de profil bulunamadı — ilişki kaydı yok.")
        return

    print()
    print(f"  {Cyan}┌─[ {Yeşil}Bu Taramada Bulunan Profiller{ Cyan} ]──────────────────┐{Bitir}")
    for s in saved:
        tag = _TAG.get(s["status"], "")
        print(f"  {Cyan}│{Bitir} [{tag}] {Yeşil}{s['platform']:<14}{Bitir} "
              f"{s['url'][:60]}")
    print(f"  {Cyan}└──────────────────────────────────────────────────────────┘{Bitir}")


def run(username, timeout=None, max_workers=6):
    print(f"\n============= {Yeşil}DEEP NICK SEARCH{Bitir} =============")

    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", username or ""):
        print(f"{Kırmızı}[✗]{Bitir} Geçersiz kullanıcı adı "
              f"(harf, rakam, _ . - izinli).")
        return

    timeout = timeout or CONFIG["app"]["timeout"]
    print(f"{Sarı}[*]{Bitir} Hedef: {Beyaz}{username}{Bitir}")
    print(f"{Sarı}[*]{Bitir} Platform sayısı: {len(PLATFORMS)}  "
          f"(paralel: {max_workers} worker)\n")

    results = []
    t_start = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_check, site, username, timeout): site
                   for site in PLATFORMS}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                site = futures[fut]
                results.append({
                    "site": site, "url": site["url"].format(u=username),
                    "status": "ERROR", "title": None,
                    "extra": str(e)[:80], "elapsed": 0,
                })

    elapsed = time.time() - t_start
    results.sort(key=lambda r: (_ORDER.get(r["status"], 99),
                                r["site"]["name"].lower()))

    for r in results:
        _print_result(r)

    stats = {"FOUND": 0, "LIKELY": 0, "UNKNOWN": 0, "NOT FOUND": 0, "ERROR": 0}
    for r in results:
        stats[r["status"]] = stats.get(r["status"], 0) + 1

    print(f"\n{Sarı}[Özet]{Bitir} "
          f"FOUND={Yeşil}{stats['FOUND']}{Bitir}  "
          f"LIKELY={Sarı}{stats['LIKELY']}{Bitir}  "
          f"UNKNOWN={Mor}{stats['UNKNOWN']}{Bitir}  "
          f"NOT FOUND={Kırmızı}{stats['NOT FOUND']}{Bitir}  "
          f"ERROR={Mor}{stats['ERROR']}{Bitir}")
    print(f"{Mor}[i]{Bitir} Toplam süre: {elapsed:.1f}s")

    saved = _correlate(username, results)
    if saved:
        print(f"{Yeşil}[✓]{Bitir} {len(saved)} profil DB'ye kaydedildi.")
    _show_relations(username, saved)