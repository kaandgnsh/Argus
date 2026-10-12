```markdown
```

┌──[argus@security-lab]─[~/ARGUS]
└─$ ./argus.py --version

█████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝

ARGUS 0.1.0 — Public OSINT & Recon Framework

```

> [!WARNING]
> **Authorized-use notice** — ARGUS yalnızca **yetkili olduğun** sistemler ve
> **kamuya açık** veriler üzerinde kullanılmak üzere tasarlanmıştır.
> Özel hesaplara giriş denemesi, authentication bypass, credential kullanımı
> veya yetkisiz sistemlere saldırı **desteklenmez**.
> Kullanımdan doğan tüm sorumluluk kullanıcıya aittir.

---

```

┌──[argus@security-lab]─[~/ARGUS]
└─$ whoami

```

## ~/identity

ARGUS, kamuya açık kaynaklardan bilgi toplamak için yazılmış modüler bir
**OSINT / recon framework**'üdür. Tek bir hedef tipi için yazılmış bir script
değil; provider sistemi üzerinden genişleyebilen, hedef tipine göre modül
çalıştıran, sonuçlarını SQLite üzerinde entity/relation olarak saklayan bir
araçtır.

- Kullanıcı adı, email, telefon, domain, IP, URL, hash, dosya, IOC
- Provider mimarisi — bir kaynak çökse diğerleri çalışmaya devam eder
- Ücretsiz/keyless API önceliği — hiçbir ücretli servis zorunlu değil
- SSRF / archive bomb / path traversal korumaları dahili
- Termux / Linux / Windows uyumlu, ağır bağımlılık yok

---

```

┌──[argus@security-lab]─[~/ARGUS]
└─$ systemctl status argus

● argus.service          active (running)
● providers.service      active (running)
● correlation.service    active (running)

```

## ~/focus

```

RECON  ──▶  ENRICH  ──▶  CORRELATE  ──▶  REPORT

```

Her hedef tipi için toplanan veriyi normalize eder, provider hatalarından
etkilenmez, ilişkileri kurar. Tahmin ile doğrulanmış bilgi birbirinden
ayrılır — `FOUND` / `LIKELY` / `UNKNOWN` / `NOT FOUND` / `ERROR`.

---

```

┌──[argus@security-lab]─[~/ARGUS]
└─$ cat toolbox.txt

```

## ~/toolbox

```

LANGUAGES
├── Python           (core)
└── Standard Library önceliği

PROVIDERS (ücretsiz / keyless)
├── Cloudflare DNS   (DoH)
├── Google DNS       (DoH)
├── RDAP             (WHOIS alternatifi)
├── crt.sh           (Certificate Transparency)
├── GitHub API       (public, rate-limited)
├── URLhaus          (abuse.ch)
├── AlienVault OTX   (public)
└── urlscan.io       (public)

SEARCH PROVIDERS
└── DuckDuckGo HTML  (Google banlı, keyless)

SECURITY
├── SSRF koruması (private IP / localhost / metadata)
├── Path traversal koruması
├── Archive bomb koruması (member/ratio/total limitleri)
├── Safe subprocess (shell=False, timeout)
└── Analiz edilen dosyalar asla çalıştırılmaz

OPTIONAL (yoksa ARGUS çalışmaya devam eder)
├── ExifTool       (resim metadata, ek)
├── Pillow         (resim EXIF)
├── pypdf          (PDF metadata)
├── ffprobe        (medya metadata)
└── python-magic   (MIME tespiti)

```

---

```

┌──[argus@security-lab]─[~/ARGUS]
└─$ ls modules/

```

## ~/modules

| # | Modül | Kapsam |
|---|-------|--------|
| 01 | **Mega Phone Search** | Numara normalizasyonu, hat tipi, operatör, ülke, WhatsApp linki, sosyal iz, ghost search |
| 02 | **Deep Nick Search** | 16 platformda false-positive filtreli kullanıcı adı taraması |
| 03 | **Email Intelligence** | Syntax, MD5/SHA256, MX, Gravatar, GitHub correlation |
| 04 | **Domain Intelligence** | DNS (A/AAAA/MX/NS/TXT/SOA/CAA), RDAP, crt.sh subdomainler |
| 05 | **DNS Intelligence** | Aynı motor, DNS odaklı |
| 06 | **IP Intelligence** | Reverse DNS, OTX reputation, URLhaus host lookup |
| 07 | **URL Intelligence** | Headers, redirect zinciri, teknoloji parmak izi |
| 08 | **Hash Lookup** | MD5 / SHA1 / SHA256 / SHA512 tip tespiti + üretimi |
| 09 | **GitHub Intelligence** | Public profil + repo listesi |
| 10 | **Threat Intelligence** | URLhaus + OTX + urlscan.io birleşik lookup |
| 11 | **File Intelligence** | EXIF / PDF / medya / arşiv / IOC extraction |
| 12 | **Dork Scanner** | 6 hazır dork şablonu + DDG üzerinden tarama |
| 13 | **Correlation** | SQLite üzerinde entity/relation grafiği + timeline |
| 14 | **Cases** | Local case yönetimi |

---

```

┌──[argus@security-lab]─[~/ARGUS]
└─$ cat install.txt

```

## ~/install

### Termux

```bash
pkg install python
git clone https://github.com/kaandgnsh/ARGUS.git
cd ARGUS
pip install -r requirements.txt
python3 argus.py
```

Linux / macOS

```bash
git clone https://github.com/kaandgnsh/ARGUS.git
cd ARGUS
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 argus.py
```

Windows (PowerShell)

```powershell
git clone https://github.com/kaandgnsh/ARGUS.git
cd ARGUS
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python argus.py
```

Opsiyonel ekler (ExifTool, Pillow, pypdf, ffprobe) için:

```bash
sh install.sh
```

---

```
┌──[argus@security-lab]─[~/ARGUS]
└─$ python3 argus.py --help
```

~/usage

İnteraktif menü

```bash
python3 argus.py
```

Tek hedef

```bash
python3 argus.py -phone    +905556667788
python3 argus.py -username kaandgn
python3 argus.py -email    user@example.com
python3 argus.py -domain   example.com
python3 argus.py -dns      example.com
python3 argus.py -ip       8.8.8.8
python3 argus.py -url      https://example.com
python3 argus.py -hash     5d41402abc4b2a76b9719d911017c592
python3 argus.py -github   torvalds
python3 argus.py -threat   8.8.8.8
python3 argus.py -file     document.pdf
python3 argus.py -dork     "site:example.com"
python3 argus.py -search   "query"
python3 argus.py -correlate kaandgn
```

Bayraklar

```
--version       Sürüm
--json          JSON çıktı (makine okunabilir)
--no-color      ANSI renkleri kapat
--debug         Debug log
--clear-cache   Cache'i temizle
```

---

```
┌──[argus@security-lab]─[~/ARGUS]
└─$ tree -L 2 --dirsfirst
```

~/layout

```
ARGUS/
├── argus.py                  entry point (menu + CLI)
├── install.sh
├── requirements.txt
├── requirements-optional.txt
├── config/
│   ├── config.json           app / http / proxy / cache / logging
│   └── providers.json        provider enable / timeout
├── core/
│   ├── banner.py             ARGUS figürü
│   ├── cache.py              SQLite TTL cache
│   ├── cli.py                argparse
│   ├── colors.py             (protected) renk bloğu
│   ├── config.py             config loader
│   ├── database.py           entities / relations / cases
│   ├── deps.py               dependency check (auto-install YOK)
│   ├── http.py               SSRF-safe HTTP client
│   ├── logger.py             rotating file log
│   ├── security.py           SSRF / path traversal / archive bomb
│   └── ui.py                 banner + menu + prompts
├── providers/
│   ├── base.py               Provider base class
│   ├── registry.py           @register decorator
│   ├── cloudflare_dns.py
│   ├── google_dns.py
│   ├── rdap.py
│   ├── crtsh.py
│   ├── github_api.py
│   ├── urlhaus.py
│   ├── otx.py
│   └── urlscan.py
├── modules/
│   ├── search.py             DDG HTML arama
│   ├── phone.py
│   ├── nickname.py
│   ├── email.py
│   ├── domain.py
│   ├── ip.py
│   ├── url.py
│   ├── hash.py
│   ├── dork.py
│   ├── github.py
│   ├── threat.py
│   ├── file_intel.py
│   ├── correlation.py
│   └── cases.py
├── tests/
│   ├── test_security.py
│   └── test_phone.py
├── cache/                    (runtime)
├── data/                     (runtime)
├── logs/                     (runtime)
└── reports/                  (runtime)
```

---

```
┌──[argus@security-lab]─[~/ARGUS]
└─$ cat provider_ekle.md
```

~/extending

Yeni bir veri kaynağı eklemek için iki dosya yeter:

1. providers/yeni_kaynak.py

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

from providers.base import Provider, ProviderUnavailable
from providers.registry import register


@register
class YeniKaynak(Provider):
    name = "yeni_kaynak"
    enabled = True
    timeout = 8
    requires_key = False

    def query(self, target):
        r = self.get("https://api.example.com/?q=" + target)
        if r.status_code != 200:
            raise ProviderUnavailable(f"yeni_kaynak: HTTP {r.status_code}")
        return r.json()
```

2. config/providers.json

```json
{
    "yeni_kaynak": { "enabled": true, "timeout": 8, "requires_key": false }
}
```

Provider hataları — timeout, 429, 403, JSON parse, DNS fail — otomatik
ProviderUnavailable'a dönüşür. ARGUS çökmez, diğerleri çalışır.

---

```
┌──[argus@security-lab]─[~/ARGUS]
└─$ cat security.md
```

~/security

Kontrol Nerede Ne yapar
SSRF guard core/security.py:is_safe_url Private IP / localhost / metadata endpoint'lerini bloklar. DNS çözümlemesini de kontrol eder.
Path traversal core/security.py:is_safe_path realpath ile base-dir dışına çıkmayı engeller.
Archive bomb core/security.py:archive_is_suspicious Member sayısı, uncompressed toplam, sıkıştırma oranı, .. yolları.
Safe subprocess modules/file_intel.py shell=False, sabit argüman listesi, 20 s timeout.
No execution Tüm file analysis Analiz edilen dosya asla çalıştırılmaz.
No auto-install core/deps.py Eksik paket raporlanır, otomatik pip install yapılmaz.

---

```
┌──[argus@security-lab]─[~/ARGUS]
└─$ pytest -q
```

~/tests

```bash
python3 -m pytest tests/ -v
```

Kapsam:

· test_security.py — private IP, SSRF URL filtresi, archive bomb, path traversal
· test_phone.py — TR numara normalizasyonu (0 / 90 / 5xx / +90 / uluslararası)

Testler gerçek kodu çağırır, mock'lanmış davranış test etmez.

---

```
┌──[argus@security-lab]─[~/ARGUS]
└─$ cat rota.md
```

~/roadmap

Şu an 0.1.0. Sonraki katmanlar:

☐ Correlation'ı otomatik akışa bağla (nickname → GitHub → email → domain)
☐ Timeline / graph export (JSON + GraphViz DOT)
☐ HTML / PDF rapor export
☐ Case system genişletmesi (entity bağlama, tag, notlar)
☐ Provider: CISA KEV, EPSS, OSV (opsiyonel, keyless)
☐ Web UI (opsiyonel, CLI'nin yerini almaz)

---

```
┌──[argus@security-lab]─[~/ARGUS]
└─$ cat kim.md
```

~/author

KaanDGN

Software Engineering öğrencisi. Linux, Networking, Cybersecurity ve
Application Security kesişiminde öğrenirken araç yayınlıyor — bitmiş ürün
değil, çalışan iş.

· GitHub: @kaandgnsh
· Odak: Linux · Networking · Application Security

---

```
┌──[argus@security-lab]─[~/ARGUS]
└─$ cat licence.md
```

~/license

MIT — bkz. LICENSE.

---

```
┌──[argus@security-lab]─[~/ARGUS]
└─$ echo "authorized use only"
authorized use only
└─$ █
```