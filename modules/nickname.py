#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Deep Nick Search — platform başına kalibre edilmiş, kanarya doğrulamalı.

Her platform için var olan (kanarya) ve olmayan bir hesabın cevabı
karşılaştırılarak çıkarılmış kurallar kullanılır:

  * Durum kodu, son adres (yönlendirme) ve sayfa içi işaretler.
  * Bazı platformlarda HTML sayfası ayırt edici olmadığı için resmi/açık
    API uçları sorgulanır (GitLab, Bluesky, Lichess, Kick, Steam XML,
    Medium RSS ...). Kullanıcıya gösterilen link yine profil sayfasıdır.
  * "Yok" sonucu ancak aynı platformda bilinen bir hesap (kanarya) hâlâ
    "var" görünüyorsa kabul edilir. Kanarya düşerse platform kısıtlama
    uyguluyor ya da sayfa yapısı değişmiş demektir: sonuç UNKNOWN olur.
  * 429/403/5xx ve tanınmayan cevaplarda bekleme süresi uzatılıp yeniden
    denenir. Kısıtlamayı aşmak için IP/proxy değiştirilmez.

Ayırt edilemeyen platformlar (giriş duvarı / bot engeli / aynı cevap)
MANUAL olarak listelenir: link verilir, karar tarayıcıda verilir.

Kurallar zamanla bozulabilir: `argus --nick-selftest` her platformda
kanaryanın VAR, rastgele bir adın YOK çıktığını doğrular.
"""

import html
import random
import re
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from core.config import CONFIG
from core import database as db


UA_DESKTOP = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
UA_MOBILE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 "
             "Mobile/15E148 Safari/604.1")
_UA = {"desktop": UA_DESKTOP, "mobile": UA_MOBILE}

# Kural alanları:
#   url        kullanıcıya gösterilen profil linki
#   probe      sorgulanan adres (yoksa url)
#   ua         "desktop" | "mobile"
#   canary     var olduğu bilinen hesap
#   found      {"status": [...], "any": [regex, ...]}  -> VAR
#   missing    {"status": [...], "any": [...], "final": [...]} -> YOK
#              Verilen her alan sağlanmalı: status listede, "any"den en az
#              biri, "all"un hepsi eşleşmeli, "none"dan hiçbiri eşleşmemeli.
#              "final": son adreste geçen parça; tek başına yeter.
#              Önce found, sonra missing denenir.
#   found_only True ise "yok" sonucu verilmez (ör. paket aramasıyla tespit)
#   wait       bu platforma istekler arası en kısa bekleme (varsayılan BASE_WAIT)
#   headers    varsayılan başlıkları değiştirir; None verilen başlık gönderilmez
# Regex'lerde {u} = re.escape(kullanıcı adı); eşleşme büyük/küçük harf
# duyarsız.
PLATFORMS = [
    # ---- Kod / geliştirici ----
    {"name": "GitHub", "url": "https://github.com/{u}", "canary": "torvalds",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "GitLab", "url": "https://gitlab.com/{u}",
     "probe": "https://gitlab.com/api/v4/users?username={u}", "canary": "sytses",
     "found": {"status": [200], "any": [r'"username":"{u}"']},
     "missing": {"status": [200], "any": [r"^\s*\[\s*\]\s*$"]}},
    {"name": "Codeberg", "url": "https://codeberg.org/{u}", "ua": "mobile",
     "canary": "fnetX",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Dev.to", "url": "https://dev.to/{u}", "canary": "ben",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Hashnode", "url": "https://hashnode.com/@{u}", "canary": "sandeep",
     "found": {"status": [200], "any": [r"<title[^>]*>[^<]*\(@{u}\)"]},
     "missing": {"status": [200], "any": [r"<title[^>]*>\s*User not found"]}},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{u}", "canary": "bitnami",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "HuggingFace", "url": "https://huggingface.co/{u}", "canary": "julien-c",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{u}", "canary": "alexisbcook",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "npm", "url": "https://www.npmjs.com/~{u}",
     "probe": "https://registry.npmjs.org/-/v1/search?text=maintainer:{u}&size=1",
     "canary": "sindresorhus", "found_only": True,
     "found": {"status": [200], "any": [r'"total":\s*[1-9]']}},
    {"name": "Keybase", "url": "https://keybase.io/{u}", "canary": "chris",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    # ---- Sosyal medya ----
    {"name": "Instagram", "url": "https://www.instagram.com/{u}/", "ua": "mobile",
     "canary": "instagram",
     # Masaüstü UA her hesaba hata rotası döner; telefon UA ayırt eder.
     "found": {"status": [200], "any": [r'"profile_id":"\d+"', r"profilePage_\d+"]},
     "missing": {"status": [200, 404], "all": [r'"pageID":"httpErrorPage"',
                                               r"comet\.igweb\.PolarisErrorRoute"]},
     "found_also": [r"instagram://user\?username={u}\b", r"instagram\.com/{u}/"],
     "block_final": ["/accounts/login", "/challenge"]},
    {"name": "X", "url": "https://x.com/{u}", "canary": "elonmusk",
     "found": {"status": [200], "any": [r"\(@{u}\)"]}, "missing": {"status": [404]}},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{u}", "ua": "mobile",
     "canary": "tiktok",
     "found": {"status": [200], "any": [r'"uniqueId":"{u}"']},
     # Olmayan hesapta kullanıcı verisi hiç gelmez; uniqueId yoksa ve
     # sayfa normal yüklendiyse (statusCode 0) yok kabul edilir.
     "missing": {"status": [200], "none": [r'"uniqueId":"'],
                 "any": [r'"statusCode":0']}},
    {"name": "YouTube", "url": "https://www.youtube.com/@{u}", "canary": "YouTube",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{u}/", "canary": "pinterest",
     "found": {"status": [200], "any": [r'"username":"{u}"']},
     "missing": {"status": [200], "none": [r'"username":"{u}"'],
                 "any": [r"<title[^>]*>\s*</title>"]}},
    {"name": "Telegram", "url": "https://t.me/{u}", "canary": "durov",
     "found": {"status": [200], "any": [r"tgme_page_title"]},
     "missing": {"status": [200], "none": [r"tgme_page_title"],
                 "any": [r"<title[^>]*>Telegram: Contact @{u}"]}},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{u}", "canary": "djkhaled305",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Tumblr", "url": "https://www.tumblr.com/{u}", "canary": "staff",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Mastodon", "url": "https://mastodon.social/@{u}", "canary": "Gargron",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Bluesky", "url": "https://bsky.app/profile/{u}.bsky.social",
     "probe": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social",
     "canary": "jay",
     "found": {"status": [200], "any": [r'"handle":"{u}\.bsky\.social"']},
     "missing": {"status": [400], "any": [r"Profile not found"]}},
    {"name": "VK", "url": "https://vk.com/{u}", "canary": "durov",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Twitch", "url": "https://www.twitch.tv/{u}", "canary": "ninja",
     # Olmayan kanalda og:title bazen hiç gelmez; <title> her zaman var.
     "found": {"status": [200], "any": [r"<title[^>]*>[^<]+ - Twitch\s*</title>"]},
     "missing": {"status": [200], "any": [r"<title[^>]*>\s*Twitch\s*</title>"]}},
    {"name": "Kick", "url": "https://kick.com/{u}",
     "probe": "https://kick.com/api/v2/channels/{u}", "canary": "xqc",
     "found": {"status": [200], "any": [r'"slug":"{u}"']},
     "missing": {"status": [404], "any": [r"Channel not found"]}},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{u}", "canary": "skrillex",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Vimeo", "url": "https://vimeo.com/{u}", "canary": "staff",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Medium", "url": "https://medium.com/@{u}",
     "probe": "https://medium.com/feed/@{u}", "canary": "ev",
     "found": {"status": [200], "any": [r"<rss"]}, "missing": {"status": [404]}},
    {"name": "Substack", "url": "https://{u}.substack.com", "canary": "platformer",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{u}", "canary": "nasahqphoto",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Dribbble", "url": "https://dribbble.com/{u}", "canary": "dribbble",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Patreon", "url": "https://www.patreon.com/{u}", "canary": "kurzgesagt",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Linktree", "url": "https://linktr.ee/{u}", "canary": "linktree",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "About.me", "url": "https://about.me/{u}", "canary": "john",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Gravatar", "url": "https://gravatar.com/{u}", "canary": "beau",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Disqus", "url": "https://disqus.com/by/{u}/", "canary": "disqus",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    # ---- Oyun ----
    {"name": "Steam", "url": "https://steamcommunity.com/id/{u}",
     "probe": "https://steamcommunity.com/id/{u}/?xml=1", "canary": "gabelogannewell",
     "wait": 3.0,
     # Accept-Language gönderilince olmayan hesaplara 429 dönüyor (ölçüldü).
     "headers": {"Accept-Language": None},
     "found": {"status": [200], "any": [r"<steamID64>\d+</steamID64>"]},
     "missing": {"status": [200], "any": [r"The specified profile could not be found"]}},
    {"name": "Chess.com", "url": "https://www.chess.com/member/{u}", "canary": "hikaru",
     "found": {"status": [200]}, "missing": {"status": [404]}},
    {"name": "Lichess", "url": "https://lichess.org/@/{u}",
     "probe": "https://lichess.org/api/user/{u}", "canary": "DrNykterstein",
     "found": {"status": [200], "any": [r'"username":"{u}"']},
     "missing": {"status": [404]}},
    # ---- Blog ----
    {"name": "WordPress", "url": "https://{u}.wordpress.com", "canary": "matt",
     "found": {"status": [200], "none_final": ["wordpress.com/typo"]},
     "missing": {"final": ["wordpress.com/typo"]}},
    {"name": "Blogger", "url": "https://{u}.blogspot.com", "canary": "googleblog",
     "found": {"status": [200]}, "missing": {"status": [404]}},
]

# Var olan ve olmayan hesap aynı cevabı alıyor ya da her şey engelli
# (2026-11 ölçümü). Yalnız link verilir.
MANUAL = [
    {"name": "Reddit", "url": "https://www.reddit.com/user/{u}",
     "why": "tüm uçlar 403 (giriş/bot engeli)"},
    {"name": "Facebook", "url": "https://www.facebook.com/{u}", "why": "her isteğe 400"},
    {"name": "Threads", "url": "https://www.threads.com/@{u}", "why": "girişe yönlendiriyor"},
    {"name": "PyPI", "url": "https://pypi.org/user/{u}/", "why": "bot doğrulama sayfası"},
    {"name": "Replit", "url": "https://replit.com/@{u}", "why": "her hesaba 404"},
    {"name": "ArtStation", "url": "https://www.artstation.com/{u}", "why": "her hesaba aynı sayfa"},
    {"name": "Behance", "url": "https://www.behance.net/{u}", "why": "her isteğe 403"},
    {"name": "Notion", "url": "https://{u}.notion.site", "why": "her hesaba aynı sayfa"},
    {"name": "Last.fm", "url": "https://www.last.fm/user/{u}", "why": "bot doğrulama sayfası"},
    {"name": "Letterboxd", "url": "https://letterboxd.com/{u}/", "why": "Cloudflare engeli"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{u}", "why": "her hesaba aynı sayfa"},
]

LIMIT_STATUS = {403, 429, 503, 502, 500, 504, 520, 521, 522}
CHALLENGE_MARKERS = ("just a moment...", "client challenge", "checking your browser",
                     "attention required", "are you a robot")

# Bu önekle başlayan açıklamalar kısıtlama/ağ kaynaklıdır: beklenip
# yeniden denenir. Diğer belirsizlikler (tanınmayan cevap) denenmez.
LIMIT_PREFIX = "kısıtlama: "

MAX_RETRY = 2            # tekli taramada kısıtlamada yeniden deneme sayısı
BASE_WAIT = 1.0          # aynı platforma istekler arası en kısa bekleme (sn)
MAX_WAIT = 20.0


# --------------------------------------------------------------------------
# Karar
# --------------------------------------------------------------------------

def _rx(pattern, username):
    return re.compile(pattern.replace("{u}", re.escape(username)), re.I | re.M)


def _cond(cond, username, code, body, final):
    """Bir found/missing koşulu sağlanıyor mu?"""
    if not cond:
        return False
    for part in cond.get("final", []):
        if part in final:
            return True
    if not any(k in cond for k in ("status", "any", "all")):
        return False
    if "status" in cond and code not in cond["status"]:
        return False
    for part in cond.get("none_final", []):
        if part in final:
            return False
    for p in cond.get("none", []):
        if _rx(p, username).search(body):
            return False
    if "any" in cond and not any(_rx(p, username).search(body) for p in cond["any"]):
        return False
    if not all(_rx(p, username).search(body) for p in cond.get("all", [])):
        return False
    return True


def verdict(platform, username, code, body, final=""):
    """True = var, False = yok, None = belirsiz (kısıtlama/engel/tanınmadı).

    İkinci değer kısa açıklamadır.
    """
    final = final or ""
    for part in platform.get("block_final", []):
        if part in final:
            return None, LIMIT_PREFIX + "giriş/doğrulama duvarı"
    # Bot doğrulama sayfası 200 dönebilir; yalnız durum koduna bakan
    # kurallar onu "var" saymasın diye her şeyden önce elenir.
    head = body[:4000].lower()
    if any(m in head for m in CHALLENGE_MARKERS):
        return None, LIMIT_PREFIX + "bot doğrulama sayfası"
    if _cond(platform.get("found"), username, code, body, final):
        extra = platform.get("found_also")
        if extra and not any(_rx(p, username).search(body) for p in extra):
            return None, "profil kimliği var ama kullanıcı adı eşleşmedi"
        return True, None
    if _cond(platform.get("missing"), username, code, body, final):
        return False, None
    if code == 410:
        # 410 Gone: hesap silinmiş/askıya alınmış (Mastodon, Flickr ölçüldü).
        return False, None
    if code in LIMIT_STATUS:
        return None, LIMIT_PREFIX + f"HTTP {code}"
    if platform.get("found_only"):
        return None, "yokluk doğrulanamaz"
    return None, f"tanınmayan cevap (HTTP {code})"


def _title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body[:200_000], re.S | re.I)
    if not m:
        return None
    t = re.sub(r"^<!\[CDATA\[(.*)\]\]>$", r"\1", m.group(1).strip(), flags=re.S)
    return " ".join(html.unescape(t).split())[:120]


# --------------------------------------------------------------------------
# Platform başına durum: hız, bekleme, kanarya
# --------------------------------------------------------------------------

class Probe:
    """Bir platforma yapılan isteklerin hızını ve kanarya durumunu tutar."""

    def __init__(self, platform, timeout):
        self.p = platform
        self.timeout = timeout
        self.base = platform.get("wait", BASE_WAIT)
        self.wait = self.base
        self.backoff = 10.0
        self._lock = threading.Lock()
        self._last = 0.0
        self._canary = None        # (zaman, sonuç)
        self._sess = threading.local()

    def _session(self):
        s = getattr(self._sess, "s", None)
        if s is None:
            s = requests.Session()
            s.headers.update({
                "User-Agent": _UA[self.p.get("ua", "desktop")],
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            })
            for k, v in (self.p.get("headers") or {}).items():
                if v is None:
                    s.headers.pop(k, None)
                else:
                    s.headers[k] = v
            self._sess.s = s
        return s

    def _pace(self):
        """Aynı platforma istekler arasında en az self.wait kadar bekle."""
        with self._lock:
            now = time.monotonic()
            t = max(now, self._last + self.wait + random.uniform(0, 0.3))
            self._last = t
        if t > now:
            time.sleep(t - now)

    def fetch(self, username):
        """(sonuç, açıklama, başlık) döner. Tek istek, yeniden deneme yok."""
        url = (self.p.get("probe") or self.p["url"]).format(u=username)
        self._pace()
        try:
            r = self._session().get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            return None, LIMIT_PREFIX + "ağ hatası " + type(e).__name__, None
        body = r.text
        res, why = verdict(self.p, username, r.status_code, body, r.url)
        return res, why, (_title(body) if res else None)

    def limited(self):
        """Kısıtlama görüldü: istek arası beklemeyi artır, geri çekil."""
        with self._lock:
            self.wait = min(max(self.wait * 2, self.base), MAX_WAIT)
            b = self.backoff
            self.backoff = min(self.backoff * 2, 600)
        return b

    def ok(self):
        with self._lock:
            self.backoff = 10.0
            if self.wait > self.base:
                self.wait = max(self.base, self.wait * 0.9)

    def check(self, username, retries=MAX_RETRY):
        """Kısıtlamada bekleyip yeniden dener."""
        for attempt in range(retries + 1):
            res, why, title = self.fetch(username)
            if res is not None:
                self.ok()
                return res, why, title
            if not (why or "").startswith(LIMIT_PREFIX):
                break
            if attempt < retries:
                time.sleep(self.limited())
        return None, why, None

    def canary_ok(self, max_age=120):
        """Kanarya hesap hâlâ VAR görünüyor mu? Sonuç kısa süre önbellekte."""
        c = self._canary
        if c and time.monotonic() - c[0] < max_age:
            return c[1]
        res, _, _ = self.check(self.p["canary"], retries=1)
        ok = res is True
        self._canary = (time.monotonic(), ok)
        return ok

    def forget_canary(self):
        self._canary = None


def _valid_username(u):
    return bool(re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", u or ""))


def _select(platforms):
    if not platforms:
        return list(PLATFORMS), list(MANUAL)
    want = {x.strip().lower() for x in platforms if x.strip()}
    sel = [p for p in PLATFORMS if p["name"].lower() in want]
    man = [p for p in MANUAL if p["name"].lower() in want]
    unknown = want - {p["name"].lower() for p in sel + man}
    if unknown:
        print(f"{Sarı}[!]{Bitir} Tanınmayan platform: {', '.join(sorted(unknown))}")
    return sel, man


# --------------------------------------------------------------------------
# Tekli tarama
# --------------------------------------------------------------------------

_TAG = {
    "FOUND":     f"{Yeşil}FOUND    {Bitir}",
    "UNKNOWN":   f"{Mor}UNKNOWN  {Bitir}",
    "NOT FOUND": f"{Kırmızı}NOT FOUND{Bitir}",
    "MANUAL":    f"{Sarı}MANUAL   {Bitir}",
}
_ORDER = {"FOUND": 0, "UNKNOWN": 1, "MANUAL": 2, "NOT FOUND": 3}


def _check_one(probe, username):
    t0 = time.time()
    res, why, title = probe.check(username)
    if res is False and not probe.canary_ok():
        res, why = None, f"kanarya ({probe.p['canary']}) görünmedi: kısıtlama ya da sayfa değişti"
    status = {True: "FOUND", False: "NOT FOUND", None: "UNKNOWN"}[res]
    return {"site": probe.p, "url": probe.p["url"].format(u=username),
            "status": status, "title": title, "extra": why,
            "elapsed": time.time() - t0}


def _print_result(r):
    status = r["status"]
    tag = _TAG.get(status, f"{Mor}?        {Bitir}")
    name = r["site"]["name"]
    if status == "FOUND":
        t = r["title"] or ""
        t = t if len(t) <= 48 else t[:47] + "…"
        title = f" {Cyan}({t}){Bitir}" if t else ""
        print(f"  [{tag}] {name:<12} {Yeşil}{r['url']}{Bitir}{title}")
    elif status in ("UNKNOWN", "MANUAL"):
        reason = f" {Mor}({r['extra']}){Bitir}" if r.get("extra") else ""
        print(f"  [{tag}] {name:<12} {r['url']}{reason}")
    else:
        print(f"  [{tag}] {name:<12}")


def _correlate(username, results):
    try:
        db.add_entity("username", username, source="nickname_module",
                      confidence="VERIFIED")
    except Exception:
        pass
    saved = []
    for r in results:
        if r["status"] != "FOUND":
            continue
        platform = r["site"]["name"]
        try:
            db.add_entity("profile", r["url"],
                          data={"platform": platform, "title": r["title"]},
                          source="nickname_module", confidence="VERIFIED")
            db.add_relation(username, r["url"], "has_profile",
                            evidence=f"{platform} — FOUND (kanarya doğrulamalı)")
        except Exception:
            pass
        saved.append({"url": r["url"], "platform": platform, "status": "FOUND"})
    return saved


def _show_relations(saved):
    if not saved:
        print(f"\n  {Mor}[i]{Bitir} Bu taramada profil bulunamadı — ilişki kaydı yok.")
        return
    print()
    print(f"  {Cyan}┌─[ {Yeşil}Bu Taramada Bulunan Profiller{Cyan} ]──────────────────┐{Bitir}")
    for s in saved:
        print(f"  {Cyan}│{Bitir} [{_TAG['FOUND']}] {Yeşil}{s['platform']:<12}{Bitir} "
              f"{s['url'][:60]}")
    print(f"  {Cyan}└──────────────────────────────────────────────────────────┘{Bitir}")


def run(username, timeout=None, max_workers=8, platforms=None):
    print(f"\n============= {Yeşil}DEEP NICK SEARCH{Bitir} =============")
    username = (username or "").strip().lstrip("@")
    if not _valid_username(username):
        print(f"{Kırmızı}[✗]{Bitir} Geçersiz kullanıcı adı (harf, rakam, _ . - izinli).")
        return []

    timeout = timeout or max(CONFIG["app"]["timeout"], 15)
    sel, man = _select(platforms)
    print(f"{Sarı}[*]{Bitir} Hedef: {Beyaz}{username}{Bitir}")
    print(f"{Sarı}[*]{Bitir} Otomatik: {len(sel)} platform  |  Elle kontrol: {len(man)}  "
          f"(paralel: {max_workers})")
    print(f"{Mor}[i]{Bitir} 'Yok' sonuçları platformun bilinen bir hesabıyla doğrulanır.\n")

    t_start = time.time()
    results = []
    probes = [Probe(p, timeout) for p in sel]
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_check_one, pr, username): pr for pr in probes}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:
                p = futs[f].p
                results.append({"site": p, "url": p["url"].format(u=username),
                                "status": "UNKNOWN", "title": None,
                                "extra": str(e)[:80], "elapsed": 0})
    for m in man:
        results.append({"site": m, "url": m["url"].format(u=username),
                        "status": "MANUAL", "title": None,
                        "extra": m["why"], "elapsed": 0})

    results.sort(key=lambda r: (_ORDER.get(r["status"], 9), r["site"]["name"].lower()))
    for r in results:
        _print_result(r)

    stats = {k: 0 for k in _ORDER}
    for r in results:
        stats[r["status"]] += 1
    print(f"\n{Sarı}[Özet]{Bitir} "
          f"FOUND={Yeşil}{stats['FOUND']}{Bitir}  "
          f"NOT FOUND={Kırmızı}{stats['NOT FOUND']}{Bitir}  "
          f"UNKNOWN={Mor}{stats['UNKNOWN']}{Bitir}  "
          f"MANUAL={Sarı}{stats['MANUAL']}{Bitir}")
    print(f"{Mor}[i]{Bitir} Toplam süre: {time.time() - t_start:.1f}s")

    saved = _correlate(username, results)
    if saved:
        print(f"{Yeşil}[✓]{Bitir} {len(saved)} profil DB'ye kaydedildi.")
    _show_relations(saved)
    return results


# --------------------------------------------------------------------------
# Öz-test
# --------------------------------------------------------------------------

def _random_name():
    return "zq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=11))


def selftest(platforms=None, timeout=None):
    """Her platformda kanarya VAR, rastgele ad YOK çıkıyor mu?"""
    print(f"\n============= {Yeşil}NICK SELF-TEST{Bitir} =============")
    sel, man = _select(platforms)
    timeout = timeout or max(CONFIG["app"]["timeout"], 15)
    fake = _random_name()
    print(f"{Sarı}[*]{Bitir} Rastgele ad: {fake}\n")

    def one(p):
        pr = Probe(p, timeout)
        a = pr.check(p["canary"], retries=2)
        b = pr.check(fake, retries=2)
        return p, a, b

    bozuk = 0
    rows = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for p, a, b in ex.map(one, sel):
            beklenen_yok = None if p.get("found_only") else False
            ok = a[0] is True and b[0] is beklenen_yok
            bozuk += not ok
            rows.append((p["name"], ok, a, b, p))
    for name, ok, a, b, p in sorted(rows, key=lambda r: (r[1], r[0].lower())):
        tag = f"{Yeşil}TAMAM {Bitir}" if ok else f"{Kırmızı}BOZUK {Bitir}"
        fmt = lambda r: {True: "VAR", False: "YOK", None: "BELİRSİZ"}[r[0]] + \
            (f" ({r[1]})" if r[1] else "")
        # Sütunlar sabit: kanarya adı uzunluğu hizayı kaydırmasın.
        print(f"  [{tag}] {name:<12} kanarya {p['canary']:<16} {fmt(a):<4} "
              f"| rastgele: {fmt(b)}")
    for m in man:
        print(f"  [{Sarı}MANUEL{Bitir}] {m['name']:<12} {m['why']}")
    print(f"\n{Sarı}[Özet]{Bitir} {len(sel) - bozuk}/{len(sel)} platform doğru ayırt ediyor.")
    if bozuk:
        print(f"{Mor}[i]{Bitir} BOZUK: kısıtlama anlık olabilir; tekrar dene. Sürerse kural "
              f"güncellenmeli (modules/nickname.py, PLATFORMS).")
    return bozuk == 0
