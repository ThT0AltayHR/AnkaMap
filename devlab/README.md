# Anka DevLab

A tiny, deliberately vulnerable Flask app used to prove Anka's detection,
dump, and WAF-bypass features actually work — entirely local, no
third-party target required.

## Run

```bash
cd anka
python devlab/app.py            # http://127.0.0.1:9911
python devlab/app.py --https    # https://127.0.0.1:9912 (self-signed cert)
```

## Endpoints

- `GET /item?id=1` — SQL injection (string-concatenated query against a
  real SQLite `users` table with fake credentials). Vulnerable to
  boolean/error/union/time-based injection.
- `GET /search?q=...` — reflected XSS (echoes `q` unescaped into HTML).
- `GET /healthz` — liveness check.

## Simulated WAF

A `before_request` hook blocks requests whose raw (undecoded) query string
or body contains one of several case-sensitive, whitespace-sensitive
SQL-injection signatures (e.g. `UNION SELECT`, `AND '1'='1`, `SLEEP(`),
mimicking a real F5 BIG-IP ASM-style attack-signature filter. Blocked
requests get a 403 page with F5-style headers (`X-Cnection: close`,
`Server: BigIP`) that Anka's `core/waf.py` fingerprints correctly.

Anka's tamper chains (`space2comment`, `randomcase`, `equaltolike`, ...)
change the literal case/whitespace of the payload just enough to slip past
this filter while the underlying SQL still executes — the same principle
real WAF bypasses rely on. `--waf-detect` in the CLI drives this
automatically.

## Proving it works

```bash
# 1. Plain payloads get blocked by the simulated WAF -> reported not vulnerable
python anka.py -u "http://127.0.0.1:9911/item?id=1" --technique B --batch

# 2. WAF-aware scan: detects the F5 signature, auto-selects a bypass chain,
#    and the same parameter is now correctly reported vulnerable
python anka.py -u "http://127.0.0.1:9911/item?id=1" --waf-detect --technique B --batch

# 3. Dump the real users table (id/username/password/role) end-to-end
python anka.py -u "http://127.0.0.1:9911/item?id=1" --waf-detect --dump-all --dbms SQLite --batch

# 4. Reflected XSS on /search
python anka.py -u "http://127.0.0.1:9911/search?q=test" --technique X --batch
```
