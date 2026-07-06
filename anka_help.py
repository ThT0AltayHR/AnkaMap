#!/usr/bin/env python3
"""
Anka's standalone, rich, bilingual (TR/EN) help screen. Run `anka-help`
from anywhere once installed, or `python3 anka_help.py` from this folder.
Shows every flag, every technique letter, and example.com usage examples
in a readable table, in both Turkish and English.
"""

import sys

from config import BANNER


def _row(cols, widths):
    return "| " + " | ".join(str(c).ljust(w) for c, w in zip(cols, widths)) + " |"


def _table(title, header, rows):
    widths = [max(len(str(header[i])), *(len(str(r[i])) for r in rows)) if rows else len(str(header[i]))
              for i in range(len(header))]
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    lines = [f"\n{title}", sep, _row(header, widths), sep]
    for r in rows:
        lines.append(_row(r, widths))
    lines.append(sep)
    return "\n".join(lines)


FLAGS_TR = [
    ("-u / --url", "Hedef URL, orn: https://www.example.com/urun.php?id=1"),
    ("--lang", "Arayuz dili: tr (varsayilan) veya en"),
    ("--data", "POST govdesi, orn: 'kullanici=a&sifre=b'"),
    ("--method", "HTTP metodu: GET veya POST"),
    ("-p / --param", "Sadece belirtilen parametreyi test et"),
    ("--cookie", "Cookie header string'i"),
    ("--header", "Ekstra header 'Isim: Deger' (tekrar edilebilir)"),
    ("--scan-cookies", "Cookie degerlerini de enjeksiyon noktasi olarak test et"),
    ("--scan-headers", "User-Agent/Referer/X-Forwarded-For header'larini test et"),
    ("--proxy", "Proxy URL (http://, socks5:// / Tor icin socks5://127.0.0.1:9050)"),
    ("--timeout / --delay / --retries", "Zaman asimi, istekler arasi gecikme, tekrar sayisi"),
    ("--time-sec / --level / --risk", "Time-based gecikme, test derinligi (1-5), risk (1-3)"),
    ("--threads", "Boolean-based test icin thread sayisi"),
    ("--stealth", "Casus modu: insan-benzeri rastgele gecikme + UA rotasyonu"),
    ("--tamper / --temper", "Virgul ile ayrilmis tamper zinciri, orn: space2comment,randomcase"),
    ("--list-tampers", "Kullanilabilir tamper scriptlerini listele"),
    ("--waf-detect / --wafbypass", "WAF tespiti yap ve dogrulanmis bypass zinciri bul"),
    ("--insecure", "HTTPS sertifika dogrulamasini kapat"),
    ("--technique", "Calistirilacak teknik harfleri (asagidaki tabloya bak)"),
    ("--crawl", "Sayfadaki ek enjekte edilebilir noktalari bul"),
    ("--subdomain", "Hedef alan adinin subdomain'lerini tara (sadece DNS)"),
    ("--auto", "Tam otomatik: WAF tespiti+bypass -> tum teknikler -> parmak izi -> dump sor"),
    ("--dump", "Veri dokumu (--all veya --table ile birlikte, tablo/kolon otomatik kesfedilir)"),
    ("--dump-all / --all", "Kesfedilen TUM tablolari tek pakette dok"),
    ("--table", "Dokulecek tablo adi/adlari (bosluk veya virgul ile ayrik)"),
    ("--dbms", "DBMS'i elle belirt (belirtilmezse otomatik tespit edilir)"),
    ("-o / --output", "Oturum verisinin yazilacagi klasor (varsayilan: sessions/)"),
    ("--resume", "Ayni URL icin onceki oturumu kaldigi yerden devam ettir"),
    ("--batch / --yes / --no", "Sorulari otomatik yanitla (batch=evet, yes=evet, no=hayir)"),
]

FLAGS_EN = [
    ("-u / --url", "Target URL, e.g. https://www.example.com/item.php?id=1"),
    ("--lang", "Interface language: tr (default) or en"),
    ("--data", "POST body, e.g. 'user=a&pass=b'"),
    ("--method", "HTTP method: GET or POST"),
    ("-p / --param", "Restrict testing to a single parameter"),
    ("--cookie", "Cookie header string"),
    ("--header", "Extra header 'Name: Value' (repeatable)"),
    ("--scan-cookies", "Also test cookie values as injection points"),
    ("--scan-headers", "Also test User-Agent/Referer/X-Forwarded-For headers"),
    ("--proxy", "Proxy URL (http://, socks5:// for Tor e.g. socks5://127.0.0.1:9050)"),
    ("--timeout / --delay / --retries", "Request timeout, delay between requests, retry count"),
    ("--time-sec / --level / --risk", "Time-based delay, test depth (1-5), risk (1-3)"),
    ("--threads", "Threads used for boolean-based testing"),
    ("--stealth", "Casus/stealth mode: human-like jittered delay + UA rotation"),
    ("--tamper / --temper", "Comma-separated tamper chain, e.g. space2comment,randomcase"),
    ("--list-tampers", "List available tamper scripts"),
    ("--waf-detect / --wafbypass", "Detect a WAF and find a verified bypass chain"),
    ("--insecure", "Disable HTTPS certificate verification"),
    ("--technique", "Technique letters to run (see table below)"),
    ("--crawl", "Discover extra injectable endpoints on the page"),
    ("--subdomain", "Enumerate subdomains of the target domain (DNS-only)"),
    ("--auto", "Full auto pipeline: WAF detect+bypass -> all techniques -> fingerprint -> ask to dump"),
    ("--dump", "Dump data (combine with --all or --table; tables/columns auto-discovered)"),
    ("--dump-all / --all", "Dump every discovered table into one bundle"),
    ("--table", "Table name(s) to dump (space or comma separated)"),
    ("--dbms", "Force a DBMS (auto-detected from fingerprinting when omitted)"),
    ("-o / --output", "Directory to write session data (default: sessions/)"),
    ("--resume", "Resume a previous session for this URL"),
    ("--batch / --yes / --no", "Auto-answer prompts (batch=yes, yes=yes, no=no)"),
]

TECHNIQUES_TR = [
    ("B", "Boolean-based blind SQLi"), ("E", "Error-based SQLi"), ("U", "UNION-based SQLi"),
    ("T", "Time-based blind SQLi"), ("X", "Yansitilan (reflected) XSS"), ("N", "NoSQL injection (Mongo tarzi)"),
    ("O", "Open redirect"), ("C", "Komut enjeksiyonu (blind, sadece tespit)"),
    ("L", "LDAP injection (blind)"), ("S", "SSRF (blind)"),
    ("H", "Guvenlik header denetimi (clickjacking / HSTS / cookie bayraklari)"),
]

TECHNIQUES_EN = [
    ("B", "Boolean-based blind SQLi"), ("E", "Error-based SQLi"), ("U", "UNION-based SQLi"),
    ("T", "Time-based blind SQLi"), ("X", "Reflected XSS"), ("N", "NoSQL injection (Mongo-style)"),
    ("O", "Open redirect"), ("C", "Command injection (blind, detect-only)"),
    ("L", "LDAP injection (blind)"), ("S", "SSRF (blind)"),
    ("H", "Security header audit (clickjacking / HSTS / cookie flags)"),
]

EXAMPLES_TR = [
    ("Temel tarama", 'anka -u "https://www.example.com/urun.php?id=1"'),
    ("Tam otomatik", 'anka -u "https://www.example.com/urun.php?id=1" --auto'),
    ("WAF bypass + tarama", 'anka -u "https://www.example.com/urun.php?id=1" --waf-detect'),
    ("Tum tabloyu dok", 'anka -u "https://www.example.com/urun.php?id=1" --dump --all'),
    ("Belirli tablo dok", 'anka -u "https://www.example.com/urun.php?id=1" --dump --table "kullanicilar siparisler"'),
    ("Subdomain tarama", 'anka -u "https://www.example.com" --subdomain'),
    ("Casus modu + tor", 'anka -u "https://www.example.com/urun.php?id=1" --stealth --proxy socks5://127.0.0.1:9050'),
]

EXAMPLES_EN = [
    ("Basic scan", 'anka -u "https://www.example.com/item.php?id=1"'),
    ("Full auto", 'anka -u "https://www.example.com/item.php?id=1" --auto'),
    ("WAF bypass + scan", 'anka -u "https://www.example.com/item.php?id=1" --waf-detect'),
    ("Dump everything", 'anka -u "https://www.example.com/item.php?id=1" --dump --all'),
    ("Dump specific tables", 'anka -u "https://www.example.com/item.php?id=1" --dump --table "users orders"'),
    ("Subdomain scan", 'anka -u "https://www.example.com" --subdomain'),
    ("Stealth mode + Tor", 'anka -u "https://www.example.com/item.php?id=1" --stealth --proxy socks5://127.0.0.1:9050'),
]


def show(lang: str):
    print(BANNER)
    if lang == "tr":
        print(_table("PARAMETRELER", ("Bayrak", "Aciklama"), FLAGS_TR))
        print(_table("TEKNIK HARFLERI (--technique BEUTXNOCLSH gibi birlestirilir)", ("Harf", "Teknik"), TECHNIQUES_TR))
        print(_table("ORNEKLER (example.com)", ("Senaryo", "Komut"), EXAMPLES_TR))
        print("\nNot: OS-shell/interaktif kabuk erisimi ve 2FA-bypass bilerek eklenmemistir (RCE/hesap ele gecirme riski).")
        print("Global kurulum icin: bash install.sh  (sonra her yerden 'anka' ve 'anka-help' calisir)\n")
    else:
        print(_table("PARAMETERS", ("Flag", "Description"), FLAGS_EN))
        print(_table("TECHNIQUE LETTERS (combine freely, e.g. --technique BEUTXNOCLSH)", ("Letter", "Technique"), TECHNIQUES_EN))
        print(_table("EXAMPLES (example.com)", ("Scenario", "Command"), EXAMPLES_EN))
        print("\nNote: OS-shell/interactive shell access and 2FA-bypass are intentionally NOT implemented (RCE / account-takeover risk).")
        print("For global install: bash install.sh  (then 'anka' and 'anka-help' work from anywhere)\n")


if __name__ == "__main__":
    lang = "tr"
    for arg in sys.argv[1:]:
        if arg in ("--lang", "-l") or arg.startswith("--lang="):
            lang = arg.split("=", 1)[1] if "=" in arg else (sys.argv[sys.argv.index(arg) + 1] if sys.argv.index(arg) + 1 < len(sys.argv) else "tr")
        if arg in ("en", "tr"):
            lang = arg
    show("en" if lang.lower().startswith("en") else "tr")
