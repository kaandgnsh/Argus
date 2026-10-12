#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""IP intelligence — multi-provider location consensus + world map + BGP + threat flags."""

import ipaddress
import socket

from core.colors import Kırmızı, Yeşil, Sarı, Beyaz, Mor, Cyan, Bitir
from providers import registry
from core.security import is_private_ip
from core import database as db


def _reverse(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _maps_link(lat, lon):
    if lat is None or lon is None:
        return None
    return f"https://www.google.com/maps?q={lat},{lon}"


def _pick_primary(sources):
    """En spesifik konum veren provider'ı seçer.

    Sıralama (spesifikten genele):
      1. ip2location  (ilçe düzeyine iner)
      2. ipinfo       (Türkiye'de tutarlı, loc koordinatı verir)
      3. ipwho.is     (bağımsız, doğrulama için iyi)
      4. ip-api       (zengin alan ama Türkiye'de İstanbul hub'ı)
    """
    priority = ["ip2location", "ipinfo", "ipwho.is", "ip-api"]
    for name in priority:
        data = sources.get(name, {})
        if "error" in data or not data:
            continue
        if data.get("lat") and data.get("lon") and data.get("city"):
            return name, data
    return None, {}


def _location_card(city, region, country, lat, lon, isp, timezone=None, source=None):
    """Kompakt konum kartı — kutu içi + tam Google Maps linki altta."""
    if not city and not country:
        return

    inner = 62
    print(f"\n  {Cyan}┌{'─' * inner}┐{Bitir}")
    title = "📍 KONUM"
    if source:
        title = f"📍 KONUM  (kaynak: {source})"
    print(f"  {Cyan}│{Bitir} {Beyaz}{title}{'' : <{inner - len(title) - 1}}{Bitir} {Cyan}│{Bitir}")
    print(f"  {Cyan}├{'─' * inner}┤{Bitir}")

    def row(label, value):
        if not value:
            return
        v = str(value)
        max_len = inner - 4 - 12
        if len(v) > max_len:
            v = v[:max_len - 3] + "..."
        padding = inner - 4 - 12 - len(v)
        print(f"  {Cyan}│{Bitir} {Sarı}{label:<12}{Bitir}{Yeşil}{v}{' ' * padding}{Bitir} {Cyan}│{Bitir}")

    row("Şehir", city)
    row("Bölge", region)
    row("Ülke", country)
    row("ISP", isp)
    row("Timezone", timezone)

    if lat is not None and lon is not None:
        row("Koordinat", f"{lat}, {lon}")

    print(f"  {Cyan}└{'─' * inner}┘{Bitir}")

    # Google Maps linki — kutu DIŞINDA, tam ve kesilmeden
    maps = _maps_link(lat, lon)
    if maps:
        print(f"  {Yeşil}🗺  Google Maps:{Bitir}")
        print(f"     {Cyan}{maps}{Bitir}")

    print(f"  {Mor}⚠  IP tabanlı konum şehir düzeyinde tahmindir.{Bitir}")


def _fetch_all_locations(ip):
    """Tüm geo provider'ları çağırır, konsensüs için normalize eder."""
    sources = {}

    p = registry.get("ip_api")
    if p and getattr(p, "enabled", True):
        try:
            j = p.query(ip)
            sources["ip-api"] = {
                "country": j.get("country"),
                "region": j.get("regionName"),
                "regionName": j.get("regionName"),
                "city": j.get("city"),
                "district": j.get("district"),
                "zip": j.get("zip"),
                "lat": j.get("lat"),
                "lon": j.get("lon"),
                "isp": j.get("isp"),
                "org": j.get("org"),
                "asn": j.get("as"),
                "as": j.get("as"),
                "timezone": j.get("timezone"),
                "proxy": j.get("proxy"),
                "hosting": j.get("hosting"),
                "mobile": j.get("mobile"),
                "reverse": j.get("reverse"),
                "raw": j,
            }
        except Exception as e:
            sources["ip-api"] = {"error": str(e)}

    p = registry.get("ipwhois_api")
    if p and getattr(p, "enabled", True):
        try:
            j = p.query(ip)
            conn = j.get("connection") or {}
            sources["ipwho.is"] = {
                "country": j.get("country"),
                "region": j.get("region"),
                "city": j.get("city"),
                "district": j.get("district"),
                "zip": j.get("postal"),
                "lat": j.get("latitude"),
                "lon": j.get("longitude"),
                "isp": conn.get("isp"),
                "org": conn.get("org"),
                "asn": conn.get("asn"),
                "timezone": (j.get("timezone") or {}).get("id"),
            }
        except Exception as e:
            sources["ipwho.is"] = {"error": str(e)}

    p = registry.get("ipinfo")
    if p and getattr(p, "enabled", True):
        try:
            j = p.query(ip)
            loc = j.get("loc", "")
            lat = lon = None
            if loc:
                parts = loc.split(",")
                if len(parts) == 2:
                    try:
                        lat = float(parts[0])
                        lon = float(parts[1])
                    except ValueError:
                        pass
            sources["ipinfo"] = {
                "country": j.get("country"),
                "region": j.get("region"),
                "city": j.get("city"),
                "district": None,
                "zip": j.get("postal"),
                "lat": lat,
                "lon": lon,
                "isp": j.get("org"),
                "org": j.get("org"),
                "asn": j.get("org", "").split()[0] if j.get("org") else None,
                "timezone": j.get("timezone"),
            }
        except Exception as e:
            sources["ipinfo"] = {"error": str(e)}

    p = registry.get("ip2location")
    if p and getattr(p, "enabled", True):
        try:
            j = p.query(ip)
            sources["ip2location"] = {
                "country": j.get("country_name"),
                "region": j.get("region_name"),
                "city": j.get("city_name"),
                "district": j.get("district"),
                "zip": j.get("zip_code"),
                "lat": j.get("latitude"),
                "lon": j.get("longitude"),
                "isp": j.get("isp"),
                "org": j.get("domain"),
                "asn": j.get("asn"),
                "timezone": j.get("time_zone"),
            }
        except Exception as e:
            sources["ip2location"] = {"error": str(e)}

    return sources


def _location_consensus(sources):
    """Farklı provider'ların sonuçlarını yan yana gösterir."""
    print(f"\n{Sarı}[*]{Bitir} Konum Uzlaşması (multi-provider)...")
    print(f"  {Mor}Türkiye'de dinamik ISP IP'leri sıklıkla İstanbul hub'ında görünür.{Bitir}\n")

    print(f"  {Beyaz}{'Provider':<14}{'Ülke':<10}{'Şehir':<18}{'İlçe':<14}{'ISP':<24}{Bitir}")
    print(f"  {Mor}{'─' * 14} {'─' * 9} {'─' * 17} {'─' * 13} {'─' * 22}{Bitir}")

    for name, data in sources.items():
        if "error" in data:
            err = data["error"][:40]
            print(f"  {Kırmızı}{name:<14} {err}{Bitir}")
            continue
        country = (data.get("country") or "-")[:9]
        city = (data.get("city") or "-")[:17]
        district = (data.get("district") or "-")[:13]
        isp = (data.get("isp") or data.get("org") or "-")[:22]
        print(f"  {Yeşil}{name:<14}{Bitir}{country:<10}{city:<18}{district:<14}{isp:<24}")

    cities = [d.get("city") for d in sources.values()
              if "error" not in d and d.get("city")]
    if cities:
        from collections import Counter
        c = Counter(cities)
        top, count = c.most_common(1)[0]
        if count >= 2 and count == len(cities):
            print(f"\n  {Yeşil}[✓]{Bitir} {Beyaz}Tüm kaynaklar aynı fikirde:{Bitir} "
                  f"{Yeşil}'{top}'{Bitir}")
        elif count >= 2:
            print(f"\n  {Sarı}[!]{Bitir} {Beyaz}Çoğunluk:{Bitir} "
                  f"{Yeşil}{count}/{len(cities)}{Bitir} kaynak {Sarı}'{top}'{Bitir} diyor.")
            others = [c2 for c2 in set(cities) if c2 != top]
            if others:
                print(f"  {Mor}   Farklı diyenler: {', '.join(others)}{Bitir}")
        else:
            print(f"\n  {Sarı}[!]{Bitir} {Beyaz}Kaynaklar uyuşmuyor — dinamik ISP IP'si olabilir.{Bitir}")


def _ip_api_details(sources):
    """ip-api detay alanlarını göster (zengin alanlar: flags, reverse, asname)."""
    data = sources.get("ip-api", {})
    if "error" in data or not data:
        return
    print(f"\n{Sarı}[*]{Bitir} ip-api.com detayları...")
    for label, key in [
        ("Country", "country"), ("Region", "regionName"),
        ("City", "city"), ("District", "district"), ("Zip", "zip"),
        ("Timezone", "timezone"),
        ("ISP", "isp"), ("Org", "org"), ("ASN", "as"), ("AS Name", "asname"),
        ("Reverse DNS", "reverse"),
    ]:
        v = data.get(key)
        if v:
            print(f"  {Beyaz}{label:<14}:{Bitir} {Yeşil}{v}{Bitir}")

    flags = []
    if data.get("proxy"):   flags.append("PROXY/VPN")
    if data.get("mobile"):  flags.append("MOBILE")
    if data.get("hosting"): flags.append("HOSTING/DATACENTER")
    if flags:
        print(f"  {Beyaz}Flags         :{Bitir} {Kırmızı}{', '.join(flags)}{Bitir}")
    else:
        print(f"  {Beyaz}Flags         :{Bitir} {Yeşil}residential (temiz){Bitir}")


def _proxycheck(ip):
    p = registry.get("proxycheck")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} proxycheck.io (VPN / Proxy / Tor)...")
    try:
        j = p.query(ip)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} proxycheck: {e}")
        return
    node = j.get(ip) or {}
    if not node:
        return
    proxy = node.get("proxy", "no")
    ptype = node.get("type", "-")
    if proxy == "yes":
        print(f"  {Beyaz}Proxy         :{Bitir} {Kırmızı}YES ({ptype}){Bitir}")
        print(f"  {Beyaz}Provider      :{Bitir} {Kırmızı}{node.get('provider', '-')}{Bitir}")
    else:
        print(f"  {Beyaz}Proxy         :{Bitir} {Yeşil}no (residential){Bitir}")
    if node.get("asn") and node["asn"] != "-":
        print(f"  {Beyaz}ASN           :{Bitir} {Yeşil}{node['asn']}{Bitir}")
    if node.get("risk") and node["risk"] != "-":
        risk = node["risk"]
        color = Kırmızı if str(risk).isdigit() and int(risk) > 66 else Yeşil
        print(f"  {Beyaz}Risk Score    :{Bitir} {color}{risk}{Bitir}")


def _tor_exit(ip):
    p = registry.get("tor_exit")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} Tor Exit Node kontrolü...")
    try:
        total = p.count()
        is_exit = p.is_exit(ip)
        if is_exit:
            print(f"  {Beyaz}Sonuç         :{Bitir} {Kırmızı}⚠ TOR EXIT NODE{Bitir}")
        else:
            print(f"  {Beyaz}Sonuç         :{Bitir} {Yeşil}Tor exit değil{Bitir}")
        if total:
            print(f"  {Beyaz}Aktif exit    :{Bitir} {Cyan}{total} (Tor Project listesi){Bitir}")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} Tor: {e}")


def _ripe_stat(ip, asn):
    p = registry.get("ripe_stat")
    if p is None or not getattr(p, "enabled", True) or not asn:
        return
    print(f"\n{Sarı}[*]{Bitir} RIPE Stat (BGP prefix + ASN overview)...")
    try:
        overview = p.as_overview(asn)
        if overview:
            print(f"  {Beyaz}ASN           :{Bitir} {Yeşil}{overview.get('resource', '?')}{Bitir}")
            if overview.get("holder"):
                print(f"  {Beyaz}Sahip         :{Bitir} {Yeşil}{overview['holder']}{Bitir}")
            if overview.get("type"):
                print(f"  {Beyaz}Tip           :{Bitir} {Yeşil}{overview['type']}{Bitir}")
            if overview.get("country"):
                print(f"  {Beyaz}Ülke          :{Bitir} {Yeşil}{overview['country']}{Bitir}")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} ASN overview: {e}")
    try:
        prefixes = p.prefixes(asn)
        if prefixes:
            print(f"  {Beyaz}Prefix sayısı :{Bitir} {Yeşil}{len(prefixes)}{Bitir}")
            for pref in prefixes[:6]:
                print(f"  {Cyan}{pref.get('prefix', '?')}{Bitir}")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} Prefix listesi: {e}")


def _internetdb(ip):
    p = registry.get("internetdb")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} InternetDB (Shodan)...")
    try:
        j = p.query(ip)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} InternetDB: {e}")
        return
    ports = j.get("ports") or []
    vulns = j.get("vulns") or []
    hostnames = j.get("hostnames") or []
    tags = j.get("tags") or []
    if ports:
        print(f"  {Beyaz}Açık portlar  :{Bitir} {Yeşil}{', '.join(str(p) for p in ports)}{Bitir}")
    else:
        print(f"  {Beyaz}Açık portlar  :{Bitir} {Mor}yok / veri yok{Bitir}")
    if hostnames:
        print(f"  {Beyaz}Hostname'ler :{Bitir} {Cyan}{', '.join(hostnames[:5])}{Bitir}")
    if tags:
        print(f"  {Beyaz}Tag'ler       :{Bitir} {Sarı}{', '.join(tags)}{Bitir}")
    if vulns:
        print(f"  {Beyaz}Zafiyetler    :{Bitir} {Kırmızı}{', '.join(vulns)}{Bitir}")
    else:
        print(f"  {Beyaz}Zafiyetler    :{Bitir} {Yeşil}yok{Bitir}")


def _threatfox(ip):
    p = registry.get("threatfox")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} ThreatFox (malware / C2 IOC)...")
    try:
        j = p.query(ip)
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} ThreatFox: {e}")
        return
    data = j.get("data") or []
    if not data:
        print(f"  {Beyaz}IOC eşleşme  :{Bitir} {Yeşil}yok{Bitir}")
        return
    print(f"  {Beyaz}Eşleşme      :{Bitir} {Kırmızı}{len(data)} IOC{Bitir}")
    for entry in data[:5]:
        malware = entry.get("malware_printable") or entry.get("malware", "?")
        threat = entry.get("threat_type", "?")
        print(f"  {Kırmızı}[{threat}]{Bitir} {Yeşil}{malware}{Bitir}")


def _otx(ip):
    p = registry.get("otx")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} AlienVault OTX...")
    try:
        j = p.query("IPv4", ip)
        print(f"  {Beyaz}Pulse count   :{Bitir} {Yeşil}{j.get('pulse_count')}{Bitir}")
        print(f"  {Beyaz}Reputation    :{Bitir} {Yeşil}{j.get('reputation')}{Bitir}")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} OTX: {e}")


def _urlhaus(ip):
    p = registry.get("urlhaus")
    if p is None or not getattr(p, "enabled", True):
        return
    print(f"\n{Sarı}[*]{Bitir} URLhaus...")
    try:
        j = p.query(ip)
        print(f"  {Beyaz}Status        :{Bitir} {Yeşil}{j.get('query_status')}{Bitir}")
        for u in (j.get("urls") or [])[:5]:
            print(f"  {Cyan}{u.get('url')}{Bitir}")
    except Exception as e:
        print(f"  {Mor}[!]{Bitir} URLhaus: {e}")


def _cidr_pivot(ip):
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return
        prefix = ".".join(parts[:3]) + "."
        entities = db.get_entities(etype="ip", limit=500)
        neighbors = [row for row in entities if row[1] != ip and row[1].startswith(prefix)]
        if neighbors:
            print(f"\n{Sarı}[*]{Bitir} CIDR pivot (aynı /24 komşuları)...")
            for etype, value, data, source, conf, ts in neighbors[:10]:
                print(f"  {Cyan}{value}{Bitir}  {Mor}({source}){Bitir}")
    except Exception:
        pass


def _correlate(ip, primary_data, primary_source):
    """IP sorgusunu correlation DB'sine kaydeder + ilişkileri gösterir."""
    try:
        db.add_entity("ip", ip, data=primary_data or {},
                      source="ip_module", confidence="VERIFIED")
        if primary_data:
            isp = primary_data.get("isp") or primary_data.get("org")
            org = primary_data.get("org")
            asn = primary_data.get("asn") or primary_data.get("as")
            country = primary_data.get("country")
            city = primary_data.get("city")
            evidence = f"via {primary_source}" if primary_source else "ip_module"
            if isp:
                db.add_entity("organization", isp, source=primary_source or "ip_module",
                              confidence="LIKELY")
                db.add_relation(ip, isp, "belongs_to_isp", evidence=evidence)
            if org and org != isp:
                db.add_entity("organization", org, source=primary_source or "ip_module",
                              confidence="LIKELY")
                db.add_relation(ip, org, "registered_to", evidence=evidence)
            if asn:
                db.add_relation(ip, asn, "announced_by", evidence=evidence)
            if country:
                db.add_entity("country", country, source=primary_source or "ip_module",
                              confidence="VERIFIED")
                db.add_relation(ip, country, "located_in", evidence=evidence)
            if city:
                db.add_entity("city", city, source=primary_source or "ip_module",
                              confidence="LIKELY")
                db.add_relation(ip, city, "located_in", evidence=evidence)
    except Exception:
        pass

    try:
        rels = db.get_relations(limit=500)
        matched = [r for r in rels if r[0] == ip or r[1] == ip]
    except Exception:
        return
    if not matched:
        print(f"\n  {Mor}[i]{Bitir} Kayıtlı ilişki yok — bu IP için ilk sorgu.")
        return

    print()
    print(f"  {Cyan}┌─[ {Yeşil}İlişkiler{ Cyan} ]─────────────────────────────────────────┐{Bitir}")
    for src, dst, kind, ev, ts in matched[:20]:
        print(f"  {Cyan}│{Bitir} {Yeşil}{src}{Bitir}  {Cyan}─[{Sarı}{kind}{Cyan}]→{Bitir}  {Yeşil}{dst}{Bitir}")
    if len(matched) > 20:
        print(f"  {Cyan}│{Bitir} {Mor}... +{len(matched) - 20} daha{Bitir}")
    print(f"  {Cyan}└──────────────────────────────────────────────────────────┘{Bitir}")


def run(ip, show_world_map=True):
    print(f"\n============= {Yeşil}IP INTELLIGENCE{Bitir} =============")
    if not ip:
        print(f"{Kırmızı}[✗]{Bitir} Boş IP.")
        return

    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        print(f"{Kırmızı}[✗]{Bitir} Geçersiz IP.")
        return

    print(f"{Sarı}[*]{Bitir} Hedef: {Beyaz}{addr}{Bitir}\n")
    print(f"  {Beyaz}Sürüm         :{Bitir} {Yeşil}IPv{addr.version}{Bitir}")
    private = is_private_ip(str(addr))
    print(f"  {Beyaz}Private       :{Bitir} "
          f"{Kırmızı if private else Yeşil}{'yes' if private else 'no'}{Bitir}")
    print(f"  {Beyaz}Global        :{Bitir} {Yeşil}{addr.is_global}{Bitir}")

    rdns = _reverse(str(addr))
    if rdns:
        print(f"  {Beyaz}Reverse DNS   :{Bitir} {Yeşil}{rdns}{Bitir}")

    # TÜM GEO PROVIDER'LARDAN veri çek
    sources = _fetch_all_locations(str(addr))

    # KONSENSÜS tablosu (hepsi yan yana)
    _location_consensus(sources)

    # ip-api detayları (zengin alanlar: flags, reverse, asname)
    _ip_api_details(sources)

    # EN SPESİFİK provider'ı seç (kart + harita için)
    primary_name, primary_data = _pick_primary(sources)

    # KONUM KARTI + DÜNYA HARİTASI
    if primary_data:
        _location_card(
            city=primary_data.get("city"),
            region=primary_data.get("region") or primary_data.get("regionName"),
            country=primary_data.get("country"),
            lat=primary_data.get("lat"),
            lon=primary_data.get("lon"),
            isp=primary_data.get("isp") or primary_data.get("org"),
            timezone=primary_data.get("timezone"),
            source=primary_name,
        )
        if show_world_map:
            try:
                from modules.graph import show_map
                show_map(str(addr), primary_data.get("lat"), primary_data.get("lon"))
            except Exception as e:
                print(f"  {Mor}[!]{Bitir} Harita: {e}")
    else:
        print(f"\n  {Mor}[i]{Bitir} Hiçbir provider geçerli konum döndürmedi.")

    # Diğer provider'lar
    _proxycheck(str(addr))
    _tor_exit(str(addr))
    asn = (sources.get("ip-api", {}).get("asn")
           or sources.get("ipinfo", {}).get("asn"))
    _ripe_stat(str(addr), asn)
    _internetdb(str(addr))
    _threatfox(str(addr))
    _otx(str(addr))
    _urlhaus(str(addr))

    # Correlation + pivot
    _correlate(str(addr), primary_data, primary_name)
    _cidr_pivot(str(addr))