"""
Anka - global configuration, legal/ethical constants, and credits.
"""

BANNER = r"""
     _        _
    / \   _ __ | | __ __ _
   / _ \ | '_ \| |/ / _` |
  / ___ \| | | |   < (_| |
 /_/   \_\_| |_|_|\_\__,_|

  Anka - Advanced Web Vulnerability & SQL Injection Testing Toolkit
  ------------------------------------------------------------------
  DEVELOPERS ......... AltayHR
  PRODUCTION ......... AltayHR
  \033[91mCOMMUNITY .......... turkhackteam.org\033[0m
  ZONE (official) .... https://zone.turksecculture.com/
  CTF ACADEMY ........ https://thtakademi.com.tr/
  License ............ GNU GPLv3 (see LICENSE)
  Anka Team - fueled by curiosity, built for authorized testing only.
"""

LANG_DEFAULT = "tr"

LEGAL_WARNING = """
==============================================================================
 LEGAL / ETHICAL NOTICE
==============================================================================
Anka is built strictly for:
  - Your own training lab (e.g. DVWA, bWAPP, Juice Shop, WebGoat, local VMs)
  - Penetration tests you are explicitly, contractually authorized to perform

Running this tool against any system you do NOT own or do NOT have written
authorization to test is illegal in most jurisdictions and is NOT permitted.

By continuing you confirm that you have explicit authorization to test the
target you provide.
==============================================================================
"""

DEFAULT_TIMEOUT = 10
DEFAULT_DELAY = 0
DEFAULT_THREADS = 1
DEFAULT_TIME_SEC = 5  # seconds used for time-based blind payloads
DEFAULT_LEVEL = 1     # 1-5, higher = more payloads/injection points tested
DEFAULT_RISK = 1       # 1-3, higher = more intrusive payloads (e.g. heavier time delays)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0",
]

INJECTION_MARKER = "*"  # marks injection point in -u/--data, like sqlmap's `*`

DUMP_DIR = "dump"       # dump/<host>.anka/ + dump/<host>.anka.zip
SESSION_DIR = "sessions"  # session/report/log data (NOT "reports/")
