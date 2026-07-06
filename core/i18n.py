"""
Minimal bilingual (Turkish / English) string catalog for Anka's
user-facing surface: banner, legal notice, CLI help snippets, and the
recurring log/report headers. Set the active language once via
set_lang("tr"|"en"); get(key) returns the string in the active language,
falling back to the key itself if untranslated (so new code never crashes
even if a string hasn't been added to the catalog yet).
"""

_LANG = {"code": "en"}

STRINGS = {
    "banner_subtitle": {
        "en": "Anka - Advanced Web Vulnerability & SQL Injection Testing Toolkit",
        "tr": "Anka - Gelismis Web Zafiyeti ve SQL Injection Test Araci",
    },
    "banner_scope": {
        "en": "For use ONLY in authorized labs / pentest engagements",
        "tr": "SADECE yetkili lab ortamlarinda / izinli sizma testlerinde kullanin",
    },
    "legal_notice_title": {
        "en": "LEGAL / ETHICAL NOTICE",
        "tr": "YASAL / ETIK UYARI",
    },
    "legal_notice_body": {
        "en": (
            "Anka is built strictly for:\n"
            "  - Your own training lab (DVWA, bWAPP, Juice Shop, WebGoat, local VMs)\n"
            "  - Penetration tests you are explicitly, contractually authorized to perform\n\n"
            "Running this tool against any system you do NOT own or do NOT have written\n"
            "authorization to test is illegal in most jurisdictions and is NOT permitted.\n\n"
            "By continuing you confirm that you have explicit authorization to test the\n"
            "target you provide."
        ),
        "tr": (
            "Anka sadece su amaclarla gelistirilmistir:\n"
            "  - Kendi egitim laboratuvariniz (DVWA, bWAPP, Juice Shop, WebGoat, yerel VM'ler)\n"
            "  - Yazili izniniz olan, sozlesmeyle yetkilendirilmis sizma testleri\n\n"
            "Sahibi olmadiginiz veya yazili test izniniz olmayan bir sisteme karsi bu araci\n"
            "calistirmak cogu ulkede yasa disidir ve KESINLIKLE izin verilmemektedir.\n\n"
            "Devam ederek, belirttiginiz hedefi test etmek icin acik izniniz oldugunu\n"
            "onaylamis olursunuz."
        ),
    },
    "auth_confirm_prompt": {
        "en": "Type 'YES' to confirm you are authorized to test this target: ",
        "tr": "Bu hedefi test etmeye yetkili oldugunuzu onaylamak icin 'EVET' yazin: ",
    },
    "auth_confirm_word": {"en": "YES", "tr": "EVET"},
    "scan_summary_title": {"en": "ANKA SCAN SUMMARY", "tr": "ANKA TARAMA OZETI"},
    "no_vulnerable": {
        "en": "No injectable parameters detected with the selected techniques.",
        "tr": "Secilen tekniklerle enjekte edilebilir bir parametre bulunamadi.",
    },
    "dump_prompt": {
        "en": "Dump the database now? 1) All tables  2) Specific table(s)  [1/2]: ",
        "tr": "Veritabani simdi dokulsun mu? 1) Tum tablolar  2) Belirli tablo(lar)  [1/2]: ",
    },
    "dump_table_prompt": {
        "en": "Enter table name(s), space-separated (e.g. users orders): ",
        "tr": "Tablo adlarini bosluk ile ayirarak girin (orn: users orders): ",
    },
    "waf_detected": {"en": "WAF detected", "tr": "WAF tespit edildi"},
    "waf_bypass_success": {"en": "bypass successful", "tr": "bypass basarili"},
    "os_shell_declined": {
        "en": (
            "[OS-SHELL] Not implemented on purpose: turning UNION/stacked-query SQLi "
            "into an interactive OS command shell is a remote-code-execution feature. "
            "Anka intentionally stops at data extraction (detection + dump), not shell "
            "access, on any target -- including your own lab."
        ),
        "tr": (
            "[OS-SHELL] Bilerek eklenmedi: UNION/stacked-query SQLi'yi interaktif bir "
            "isletim sistemi komut satirina cevirmek, uzaktan kod calistirma (RCE) "
            "ozelligidir. Anka, kendi lab ortaminiz dahil hicbir hedefte kabuk erisimine "
            "degil, veri cikarmaya (tespit + dump) kadar gider."
        ),
    },
}


def set_lang(code: str) -> None:
    _LANG["code"] = "tr" if str(code).lower().startswith("tr") else "en"


def get_lang() -> str:
    return _LANG["code"]


def t(key: str) -> str:
    entry = STRINGS.get(key)
    if not entry:
        return key
    return entry.get(_LANG["code"], entry.get("en", key))
