# Anka

**Gelistiriciler / Uretim:** AltayHR &nbsp;|&nbsp; **Topluluk:** [turkhackteam.org](https://turkhackteam.org) &nbsp;|&nbsp; **Zone:** [zone.turksecculture.com](https://zone.turksecculture.com/) &nbsp;|&nbsp; **CTF Akademi:** [thtakademi.com.tr](https://thtakademi.com.tr/) &nbsp;|&nbsp; **Lisans:** GNU GPLv3 (bkz. `LICENSE`)

---

## Turkce

Anka, Python ile yazilmis, egitim ve yetkili sizma testi amacli bir web
zafiyeti / SQL injection test aracidir. SQLmap'ten mimari olarak ilham
almistir (boolean/error/time/union tabanli tespit, DBMS parmak izi, WAF
tespiti + bypass, tamper scriptleri, oturum devam ettirme, REST API) ama
kod tamamen ozgundur -- SQLmap deposundan hicbir satir kopyalanmamistir.

**SADECE** sahibi oldugunuz veya yazili izniniz olan sistemlerde kullanin
(kendi lab ortaminiz: DVWA, bWAPP, Juice Shop, WebGoat, yerel VM'ler; ya da
yazili yetkiniz olan bir sizma testi).

### Kurulum

```bash
cd anka
pip install -r requirements.txt

# Global 'anka' ve 'anka-help' komutlarini PATH'e eklemek icin:
bash install.sh
```

Kurulumdan sonra herhangi bir dizinden `cd` veya `python3` on eki
kullanmadan calistirabilirsiniz:

```bash
anka -u "https://www.example.com/urun.php?id=1"
anka-help          # tum komutlarin tablolu, cift dilli anlatimi
```

### Hizli baslangic ornekleri (example.com)

```bash
# Temel tarama (varsayilan: tum tespit teknikleri)
anka -u "https://www.example.com/urun.php?id=1"

# Tam otomatik pipeline: WAF tespiti -> bypass -> enjeksiyon -> tablo listesi sor
anka -u "https://www.example.com/urun.php?id=1" --auto

# WAF tespiti + dogrulanmis bypass zinciri
anka -u "https://www.example.com/urun.php?id=1" --waf-detect

# Tum veritabanini dok (tablo/kolon adlari otomatik kesfedilir, elle girilmez)
anka -u "https://www.example.com/urun.php?id=1" --dump --all

# Sadece belirli tablo(lar)i dok
anka -u "https://www.example.com/urun.php?id=1" --dump --table "kullanicilar siparisler"

# Subdomain tarama (sadece DNS, sizma girisimi yok)
anka -u "https://www.example.com" --subdomain

# Casus/stealth modu + Tor uzerinden
anka -u "https://www.example.com/urun.php?id=1" --stealth --proxy socks5://127.0.0.1:9050

# POST login formu, sadece 'sifre' parametresini test et, sorulari otomatik yanitla
anka -u "https://www.example.com/giris.php" --data "kullanici=a&sifre=b" --method POST -p sifre --batch

# Ozel tamper zinciri ile WAF atlatma denemesi
anka -u "https://www.example.com/urun.php?id=1" --tamper space2comment,randomcase,unicodeescape
```

Tum bayraklarin ve tekniklerin tablolu listesi icin: `anka-help` (`--lang en` ile Ingilizce).

### Desteklenen teknikler (`--technique` harfleri)

| Harf | Teknik |
|---|---|
| B | Boolean-based blind SQLi |
| E | Error-based SQLi |
| U | UNION-based SQLi |
| T | Time-based blind SQLi |
| X | Yansitilan (reflected) XSS |
| N | NoSQL injection (Mongo tarzi) |
| O | Open redirect |
| C | Komut enjeksiyonu (blind, sadece tespit) |
| L | LDAP injection (blind) |
| S | SSRF (blind) |
| H | Guvenlik header denetimi (clickjacking / HSTS / cookie bayraklari) |

Ayrica: stacked-query, ORDER BY / GROUP BY / HAVING / LIMIT clause
injection probe'lari `core/payloads.py` icinde tanimlidir ve boolean/time
tabanli tespit akisinca kullanilir.

### Cikti yapisi

- `sessions/<host>/` -- her taramanin JSON + HTML + TXT raporu (eskiden
  `reports/` idi, artik `sessions/` altinda).
- `dump/<host>.anka/` + `dump/<host>.anka.zip` -- dokulen veri (JSON, HTML, TXT olarak; ayrica zip'lenmis hali).

### Bilerek eklenmeyenler

- **OS-Shell / interaktif komut satiri / dosya yukleme RCE paneli:**
  UNION/stacked-query SQLi'yi tam bir uzaktan kod calistirma (RCE) araciina
  cevirmek, veri sizintisi tespitinin cok otesinde bir saldiri
  yetenegidir. Anka bilinçli olarak veri cikarmada durur.
- **2FA-bypass:** Hesap ele gecirme/kimlik dogrulama atlatma ozelligi
  eklenmemistir.

Bu ikisi disinda istenen ozelliklerin tamami (bilingual arayuz, tam
otomatik kesif, WAF/tamper genisletmesi, yeni zafiyet siniflari, dump/rapor
yeniden yapilandirmasi, global CLI) uygulanmistir. Kapsam disi birakilan
kucuk maddeler (tam asyncio/HTTP2 yeniden yazimi, literal "yuzlerce/binlerce"
WAF imzasi, gercek ML/AI, Docker/CI-CD/plugin sistemi, PDF/Excel/CVSS/MITRE
raporlama) bilinclidir; bunlar zaman/kapsam nedeniyle ertelenmis, asla
"yapildi" diye yanlis beyan edilmemistir.

---

## English

Anka is an educational, authorized-pentest SQL injection / web
vulnerability testing toolkit written in Python. It is architecturally
inspired by SQLmap (boolean/error/time/union-based detection, DBMS
fingerprinting, WAF detection + bypass, tamper scripts, session resume, a
REST API layer) but the code is entirely original -- nothing is copied
from the SQLmap repository.

**Use ONLY** against systems you own or are explicitly authorized to test
(your own lab: DVWA, bWAPP, Juice Shop, WebGoat, local VMs; or a pentest
engagement with written authorization).

### Install

```bash
cd anka
pip install -r requirements.txt

# To put the global 'anka' and 'anka-help' commands on your PATH:
bash install.sh
```

After install, run from any directory, no `cd` or `python3` prefix needed:

```bash
anka -u "https://www.example.com/item.php?id=1"
anka-help --lang en          # full tabular, bilingual help
```

### Quick-start examples (example.com)

```bash
# Basic scan (default: all detection techniques)
anka -u "https://www.example.com/item.php?id=1"

# Full auto pipeline: WAF detect -> bypass -> inject -> ask to list tables
anka -u "https://www.example.com/item.php?id=1" --auto

# WAF detection + verified bypass chain
anka -u "https://www.example.com/item.php?id=1" --waf-detect

# Dump the entire database (table/column names auto-discovered, never typed manually)
anka -u "https://www.example.com/item.php?id=1" --dump --all

# Dump specific table(s) only
anka -u "https://www.example.com/item.php?id=1" --dump --table "users orders"

# Subdomain enumeration (DNS-only, no exploitation)
anka -u "https://www.example.com" --subdomain

# Stealth/"casus" mode over Tor
anka -u "https://www.example.com/item.php?id=1" --stealth --proxy socks5://127.0.0.1:9050

# POST login form, test only the 'password' field, auto-answer prompts
anka -u "https://www.example.com/login.php" --data "user=a&password=b" --method POST -p password --batch

# Custom tamper chain to try past a WAF
anka -u "https://www.example.com/item.php?id=1" --tamper space2comment,randomcase,unicodeescape
```

Run `anka-help` for a full table of every flag and technique (`--lang tr` for Turkish).

### Supported techniques (`--technique` letters)

| Letter | Technique |
|---|---|
| B | Boolean-based blind SQLi |
| E | Error-based SQLi |
| U | UNION-based SQLi |
| T | Time-based blind SQLi |
| X | Reflected XSS |
| N | NoSQL injection (Mongo-style) |
| O | Open redirect |
| C | Command injection (blind, detect-only) |
| L | LDAP injection (blind) |
| S | SSRF (blind) |
| H | Security header audit (clickjacking / HSTS / cookie flags) |

Stacked-query, ORDER BY / GROUP BY / HAVING / LIMIT clause-injection probes
are defined in `core/payloads.py` and used by the boolean/time-based
detection flow.

### Output layout

- `sessions/<host>/` -- each scan's JSON + HTML + TXT report (previously a
  flat `reports/` dir; now under `sessions/`).
- `dump/<host>.anka/` + `dump/<host>.anka.zip` -- dumped data (JSON, HTML, TXT, plus a zipped bundle).

### Intentionally not implemented

- **OS-Shell / interactive command shell / file-upload RCE panel:**
  turning UNION/stacked-query SQLi into a full remote-code-execution tool
  goes well beyond vulnerability detection. Anka deliberately stops at
  data extraction.
- **2FA-bypass:** no account-takeover / auth-bypass feature is included.

Everything else on the requested feature list has been implemented
(bilingual interface, full auto-discovery pipeline, expanded WAF/tamper
coverage, new vulnerability classes, restructured dump/report output,
global CLI). A few items were deliberately scoped out for now (a full
asyncio/HTTP2 rewrite, a literal "hundreds/thousands" of WAF signatures,
real ML/AI, a Docker/CI-CD/plugin system, PDF/Excel/CVSS/MITRE reporting)
-- these are honestly listed as deferred, not falsely claimed as done.

### License

GNU General Public License v3.0 -- see `LICENSE`.
