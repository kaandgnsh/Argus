# ARGUS

Kamuya açık kaynaklardan bilgi toplamak, bulguları ilişkilendirmek ve yerel raporlar üretmek için modüler Python OSINT / recon aracı.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://github.com/kaandgnsh/Argus/actions/workflows/tests.yml/badge.svg)

> [!WARNING]
> ARGUS'u yalnızca yetkili olduğun hedeflerde ve kullanımına izin verilen verilerle çalıştır. Telefon sorguları, yapılandırmaya göre numarayı üçüncü taraf API'lerine ve arama sağlayıcılarına iletebilir. Hassas veri girmeden önce **Gizlilik ve güvenlik** bölümünü oku.

## ✨ Özellikler

- **Çoklu hedef türü:** kullanıcı adı, e-posta, telefon, domain/DNS, IP, URL, hash, GitHub profili, IOC ve yerel dosya.
- **Provider tabanlı mimari:** DNS, RDAP, Certificate Transparency ve tehdit istihbaratı kaynaklarını modüler biçimde kullanır.
- **Yerel kayıt:** bulguları SQLite üzerinde entity ve ilişki olarak saklar; case yönetimi sunar.
- **Raporlama:** JSON, HTML, CSV, Markdown ve GraphViz DOT dışa aktarımı.
- **Dosya analizi:** hash üretimi, IOC çıkarımı, arşiv incelemesi ve isteğe bağlı EXIF/PDF/medya metadata desteği.
- **Güvenlik kontrolleri:** HTTP istemcisinde URL/redirect kontrolleri; arşivlerde üye sayısı, açılmış boyut ve yol denetimleri.
- **Harici araç yönetimi:** desteklenen sistemlerde isteğe bağlı araç kurulumunu kullanıcı onayıyla başlatır.
- **Otomatik paket kurulumu yok:** temel bağımlılıklar açıkça pip ile kurulur; isteğe bağlı özellikler ek paket gerektirebilir.

## 📦 Kurulum

### Gereksinimler

- Python 3.10 veya üstü
- Git
- Zorunlu Python paketleri: requests, beautifulsoup4, phonenumbers, dnspython

### Linux / macOS / Termux

```bash
git clone https://github.com/kaandgnsh/Argus.git
cd Argus

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python argus.py --version
```

Termux'ta önce pkg install python git komutunu çalıştır.

### Windows (PowerShell)

```powershell
git clone https://github.com/kaandgnsh/Argus.git
cd Argus

py -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python argus.py --version
```

### İsteğe bağlı bağımlılıklar

Dosya türüne göre yalnızca ihtiyacın olan ekleri kur. Örneğin:

```bash
python -m pip install Pillow pypdf exifread
```

python-magic işletim sistemine bağlı ek sistem kütüphaneleri gerektirebilir. Telegram telefon numarası kontrolü gibi ayrı entegrasyonları yalnızca bilerek kullanacaksan kur.

## 🚀 Kullanım

### Hızlı örnekler

```bash
# İnteraktif menü
python3 argus.py

# Domain / DNS ve IP bilgileri
python3 argus.py -domain example.com
python3 argus.py -dns example.com
python3 argus.py -ip 8.8.8.8 --no-map

# Kullanıcı adı, e-posta ve GitHub
python3 argus.py -username kaandgnsh
python3 argus.py -email user@example.com
python3 argus.py -github torvalds

# URL, hash ve tehdit göstergesi
python3 argus.py -url https://example.com
python3 argus.py -hash 5d41402abc4b2a76b9719d911017c592
python3 argus.py -threat 8.8.8.8

# Yetkili olduğun hedefler için arama
python3 argus.py -search "site:example.com security.txt"
python3 argus.py -dork "site:example.com"

# Yerel dosya ve EXIF analizi
python3 argus.py -file document.pdf
python3 argus.py -exif photo.jpg

# Veritabanında kayıtlı bulguları dışa aktar
python3 argus.py --export-all
```

**--export-all** yeni tarama başlatmaz; SQLite veritabanında o ana kadar birikmiş kayıtları raporlar. Telefon numarası analizi ise yapılandırılmış provider'ları ve arama sağlayıcılarını kullanabilir; bir sorgunun yerel kaldığını varsayma.

## ⚙️ CLI seçenekleri

| Seçenek | Açıklama |
|---|---|
| **-phone NUMBER** | Telefon numarası analizi; üçüncü taraf sorguları çalıştırabilir |
| **-username / -u USER** | Kullanıcı adı için çoklu platform kontrolü |
| **-email EMAIL** | E-posta istihbaratı |
| **-domain DOMAIN** | Domain istihbaratı ve alt domain bilgileri |
| **-dns DOMAIN** | DNS odaklı domain sorgusu |
| **-ip IP** | IP istihbaratı; --no-map haritayı gizler |
| **-url URL** | URL / HTTP başlıkları ve yönlendirme analizi |
| **-hash VALUE** | Hash türü tespiti ve hash üretimi |
| **-github USER** | Kamuya açık GitHub profili ve repo bilgileri |
| **-threat IOC** | IP/domain/URL/hash gibi tehdit göstergesi sorgusu |
| **-file PATH** | Yerel dosya analizi ve IOC çıkarımı |
| **-exif IMAGE** | Görsel metadata analizi; --save-thumb thumbnail kaydeder |
| **-dork QUERY** | Arama motoruyla dork sorgusu |
| **-search QUERY** | Genel web araması |
| **-correlate QUERY** | Yerel veritabanındaki ilişkileri incele |
| **--export-json** | JSON raporu üret |
| **--export-html** | HTML raporu üret |
| **--export-csv** | Entity ve ilişki CSV dosyalarını üret |
| **--export-md** | Markdown raporu üret |
| **--export-dot** | GraphViz ilişki grafiği üret |
| **--export-all** | Desteklenen tüm raporları üret |
| **--list-tools** | Harici araçların durumunu listele |
| **--install-tools TOOL** | Belirtilen aracı kullanıcı onayıyla kurmayı dene |
| **--no-color** | Renkli terminal çıktısını kapat |
| **--debug** | Debug seviyesinde günlükleme |
| **--clear-cache** | Yerel cache'i temizle |
| **--json** | JSON stdout çıktısı; şu anda -search ve -exif akışlarında desteklenir |
| **--subdomain-log PATH** | Alt domain listesini dosyaya yaz |

Araç adlarını görmek için python3 argus.py --list-tools kullan. Kurulumdan önce gösterilen komutu incele; ARGUS sistem paket yöneticisini çalıştırmadan önce onay ister.

## 🔐 Gizlilik ve güvenlik

- **Telefon sorguları:** telefon numarası; yapılandırılmış ve etkin provider'lara, ayrıca sosyal/şikâyet sitesi araması için DuckDuckGo veya Bing'e gönderilebilir. Üçüncü tarafların kendi saklama politikaları geçerlidir.
- **Provider ayarları:** config/providers.json dosyasında ihtiyacın olmayan provider'ları enabled: false yap. API anahtarlarını kaynak koduna veya Git'e yazma; sağlayıcının dokümantasyonunda belirtilen ortam değişkenlerini kullan.
- **Yerel kayıtlar:** entity ve ilişki verileri data/argus.sqlite içinde; raporlar reports/, günlükler logs/ altında tutulur. Bu klasörler hedeflere ait hassas bulgular içerebilir.
- **HTTP kontrolleri:** URL ve yönlendirme hedefleri kontrol edilir, ancak hiçbir uygulama katmanı kontrolünü mutlak güvenlik garantisi olarak değerlendirme. ARGUS'u güncel tut ve bulguları kaynağından doğrula.
- **Dosya analizi:** yalnızca incelemeye yetkili olduğun dosyaları aç. Bilinmeyen dosyalar çalıştırılmaz; harici metadata araçları ayrı süreçlerde zaman aşımıyla çalışır.

## 🧪 Testler

```bash
python -m pip install pytest
python -m pytest -q
```

Test kapsamı güvenlik yardımcılarını, telefon numarası normalizasyonunu, rapor dışa aktarmayı ve CLI yönlendirmelerini içerir. GitHub Actions, testleri Python 3.10–3.12 üzerinde çalıştırır.

## 📁 Proje yapısı

```text
Argus/
├── argus.py
├── requirements.txt
├── requirements-optional.txt
├── install.sh
├── config/
│   ├── config.json
│   └── providers.json
├── core/
│   ├── cache.py
│   ├── cli.py
│   ├── config.py
│   ├── database.py
│   ├── deps.py
│   ├── http.py
│   ├── logger.py
│   ├── reports.py
│   ├── security.py
│   ├── tools.py
│   └── ui.py
├── modules/
│   ├── phone.py
│   ├── nickname.py
│   ├── email.py
│   ├── domain.py
│   ├── ip.py
│   ├── url.py
│   ├── hash.py
│   ├── github.py
│   ├── threat.py
│   ├── file_intel.py
│   ├── exif.py
│   ├── dork.py
│   ├── correlation.py
│   └── cases.py
├── providers/
└── tests/
```

## 🤝 Katkı

1. Fork oluştur.
2. Ayrı bir dal aç: git checkout -b fix/kisa-aciklama
3. Değişikliği ve testleri ekle.
4. python -m pytest -q çalıştır.
5. Pull request aç ve davranış değişikliklerini açıkla.

## 📜 Lisans

MIT License. Ayrıntılar için [LICENSE](LICENSE) dosyasına bak.

## 👤 Yazar

**KaanDGN** · [GitHub](https://github.com/kaandgnsh) · [Instagram](https://instagram.com/kaandgn.sh)
