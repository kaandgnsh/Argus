#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Nick kurallarının ağsız testleri (gerçek cevaplardan kısaltılmış örnekler)."""

from modules.nickname import PLATFORMS, MANUAL, verdict, LIMIT_PREFIX


def P(name):
    return next(p for p in PLATFORMS if p["name"] == name)


def test_platform_fields():
    names = [p["name"] for p in PLATFORMS] + [m["name"] for m in MANUAL]
    assert len(names) == len(set(names))
    for p in PLATFORMS:
        assert "{u}" in p["url"] and p.get("canary") and p.get("found")
        if not p.get("found_only"):
            assert p.get("missing"), p["name"]


def test_status_only():
    gh = P("GitHub")
    assert verdict(gh, "torvalds", 200, "<html>")[0] is True
    assert verdict(gh, "x", 404, "<html>")[0] is False
    res, why = verdict(gh, "x", 429, "")
    assert res is None and why.startswith(LIMIT_PREFIX)


def test_instagram():
    ig = P("Instagram")
    var = ('"pageID":"httpErrorPage" "profile_id":"25025320" '
           'al:ios:url" content="instagram://user?username=instagram"')
    yok = '"pageID":"httpErrorPage" "canonicalRouteName":"comet.igweb.PolarisErrorRoute"'
    kabuk = '<title>Instagram</title> httpErrorPage'   # masaüstü/limit kabuğu
    assert verdict(ig, "instagram", 200, var)[0] is True
    assert verdict(ig, "zqxv9182abc", 200, yok)[0] is False
    assert verdict(ig, "x", 200, kabuk)[0] is None
    assert verdict(ig, "x", 200, var, "https://www.instagram.com/accounts/login/")[0] is None
    # Profil kimliği başka kullanıcıya aitse kabul etme.
    assert verdict(ig, "baska", 200, var)[0] is None


def test_tiktok_telegram_pinterest():
    tt = P("TikTok")
    assert verdict(tt, "tiktok", 200, '"statusCode":0 "uniqueId":"tiktok"')[0] is True
    assert verdict(tt, "zz", 200, '"statusCode":0')[0] is False
    assert verdict(tt, "zz", 200, '<title>captcha</title>')[0] is None
    tg = P("Telegram")
    assert verdict(tg, "durov", 200, '<div class="tgme_page_title">')[0] is True
    assert verdict(tg, "zz", 200, "<title>Telegram: Contact @zz</title>")[0] is False
    pin = P("Pinterest")
    assert verdict(pin, "pinterest", 200, '"username":"pinterest"')[0] is True
    assert verdict(pin, "zz", 200, "<title></title>")[0] is False


def test_api_platforms():
    assert verdict(P("GitLab"), "sytses", 200, '[{"id":1,"username":"sytses"}]')[0] is True
    assert verdict(P("GitLab"), "zz", 200, "[]")[0] is False
    assert verdict(P("Bluesky"), "zz", 400, '{"message":"Profile not found"}')[0] is False
    assert verdict(P("Steam"), "zz", 200,
                   "<error><![CDATA[The specified profile could not be found.]]>")[0] is False
    assert verdict(P("Steam"), "g", 200, "<steamID64>76561197960287930</steamID64>")[0] is True


def test_wordpress_twitch_npm():
    wp = P("WordPress")
    assert verdict(wp, "zz", 200, "x", "https://wordpress.com/typo/?subdomain=zz")[0] is False
    assert verdict(wp, "matt", 200, "x", "https://matt.blog/")[0] is True
    tw = P("Twitch")
    assert verdict(tw, "ninja", 200, "<title>Ninja - Twitch</title>")[0] is True
    assert verdict(tw, "zz", 200, "<title>Twitch</title>")[0] is False
    npm = P("npm")
    assert verdict(npm, "s", 200, '{"objects":[],"total":12}')[0] is True
    assert verdict(npm, "zz", 200, '{"objects":[],"total":0}')[0] is None


def test_challenge_page_is_unknown():
    res, why = verdict(P("Dev.to"), "zz", 200, "<title>Just a moment...</title>")
    assert res is None and why.startswith(LIMIT_PREFIX)


def test_gone_and_cdata_title():
    from modules.nickname import _title
    assert verdict(P("Mastodon"), "zz", 410, "")[0] is False
    assert _title("<title><![CDATA[Stories by Ev on Medium]]></title>") == "Stories by Ev on Medium"
