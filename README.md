# VulnWeb-Lab

A deliberately vulnerable web application for learning and for training AI
agents. One codebase, **two interfaces**:

| Interface | URL | Purpose |
|---|---|---|
| **OrbitDesk** | `/` | A realistic customer-support SaaS with vulnerabilities hidden inside normal features. No hints, no labels. |
| **Academy** | `/lab` | Every vulnerability as a guided lesson: concept, objective, step-by-step walkthrough, hints, a working example request, flag submission, and remediation. |

**248 individually flagged vulnerabilities** across **21 families**, each with a
recorded flag, a machine-readable manifest, and an automated exploit test.

> [!WARNING]
> This application is intentionally insecure. It runs real shell commands and
> reads local files for some exercises. Run it **only** in the provided
> container or an isolated VM, bind it to `127.0.0.1`, and never expose it to
> the internet or a shared network. It is for authorized training only.

---

## Catalog

| Family | Count | What it covers |
|---|---:|---|
| `sqli` | 24 | Login bypass, UNION extraction, numeric injection, space/WAF bypasses |
| `xss` | 24 | HTML, attribute, JavaScript, URL, textarea, title, JSON, markdown contexts |
| `stored-xss` | 12 | Persistent comments, profiles, reviews, wiki, announcements |
| `cmdi` | 16 | Shell metacharacter injection in ping/DNS/whois/convert/archive tools |
| `traversal` | 16 | `../`, `....//` filter bypasses, attachment and backup readers |
| `ssrf` | 14 | Loopback/metadata fetches, allowlist bypass, decimal IP bypass |
| `idor` | 20 | Cross-tenant tickets, invoices, users, files, payments, audit entries |
| `auth` | 16 | Default creds, predictable resets, unsigned/weak JWTs, OTP, 2FA, session fixation |
| `redirect` | 12 | Open redirects and trusted-prefix allowlist bypasses |
| `ssti` | 12 | Jinja template injection with alternate syntax when `{{ }}` is blocked |
| `upload` | 10 | Active HTML/SVG, content-type spoofing, double extensions, zip-slip, overwrite |
| `logic` | 16 | Negative quantity, price tampering, coupon stacking, race, self-approval |
| `info` | 20 | Debug/backups, CORS with credentials, missing headers, CSRF, CRLF injection |
| `nosql` | 6 | `$ne`, `$gt`, `$regex`, `$or`, `$in`, `$where` authentication bypasses |
| `ldap` | 4 | Filter injection in directory search and LDAP auth |
| `xxe` | 6 | XML external entities reading local files through SAX parsers |
| `host-header` | 4 | Poisoned Host/X-Forwarded-Host in reset and invitation links |
| `hpp` | 4 | Duplicate parameters that flip a privileged decision |
| `cache` | 4 | Web cache poisoning via reflected X-Forwarded-Host |
| `csv-injection` | 4 | Spreadsheet formula injection in CSV exports |
| `email-injection` | 4 | CRLF header injection in contact and invite forms |
| **Total** | **248** | |

Every entry has a unique ID (for example `sqli-05`), route, parameter,
difficulty, CWE, OWASP mapping, and a flag in the form
`FLAG{orbit_<id>_<token>}`.

---

## Quick start

### Local

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
python run.py                 # both interfaces on http://127.0.0.1:8080
```

Two separate processes, if you prefer:

```bash
python run.py --mode site --port 8080   # OrbitDesk only
python run.py --mode lab  --port 8081   # Academy only (site endpoints remain targets)
```

Modes:

- `site` — only the realistic OrbitDesk interface.
- `lab` — the Academy; `/` redirects to `/lab`, all site endpoints stay reachable as targets.
- `both` — OrbitDesk at `/`, Academy at `/lab` (default).
- `--exam` — OrbitDesk only, with every answer endpoint hidden and flags kept in memory (see below).

```bash
python run.py --exam            # equivalent to RANGE_EXAM=1
```

### Docker

```bash
docker compose up --build
```

The compose file publishes the port to `127.0.0.1` only and runs as a non-root
user. Set `RANGE_SECRET` to keep flags stable across restarts. For an exam run,
set `RANGE_EXAM: "1"` instead; exam mode ignores `RANGE_SECRET` and rotates flags.

---

## Exam mode (agent evaluation)

Guided mode is for learning: the Academy shows the exact payload and the vault
contains the flags. **Exam mode** is for measuring an agent that should not see
the answers:

```bash
python run.py --exam
# or
RANGE_EXAM=1 python run.py
```

What changes:

| Guided mode | Exam mode |
|---|---|
| `/lab` lessons with exact payloads | `/lab` returns **404** |
| `/api/catalog` route manifest | `/api/catalog` returns **404** |
| `/api/solves` progress feed | `/api/solves` returns **404** |
| Stable flags, written to `instance/vault` | Flags live **in memory only**, rotate each start |
| `instance/secret.key` + `range.db` on disk | No secret, database, or flag vault on disk |
| One SQLite database holds every flag | Each SQLi challenge gets its **own** database with one flag |
| Command injection can read the shared vault | Child sees only `RANGE_FLAG` for that challenge |
| Traversal reads a shared flag file | Traversal returns only that challenge's virtual flag |

`POST /api/verify` remains available for scoring. Everything still holds 248
individual flags; they are simply not co-located, so one RCE or SQL injection
cannot harvest the other 221.

Residual risks and recommendations:

- Source files (`app/handlers.py`, `tools/exploit_all.py`) still contain the
  answers. Run the range in a container and the agent in a **separate**
  container with only the base URL — no repository or `instance/` mount.
- A clean exam host should not contain the guided `instance/` folder. Exam mode
  uses `instance-exam/`, but an RCE could still read a leftover `instance/vault`
  if both exist on the same filesystem. Use a fresh container for exams.
- Verify an exam deployment with:

```bash
RANGE_EXAM=1 python tools/exploit_all.py --base http://127.0.0.1:8080
```

---

## Safety controls

| Control | Behavior |
|---|---|
| `RANGE_HOST=127.0.0.1` | Default bind address; do not change on a shared machine. |
| `RANGE_SAFE=1` | Disables command injection, path traversal, and `file://` SSRF. |
| Non-root container | Docker image creates and uses a `range` user. |
| No external SSRF | The SSRF exercises resolve internal destinations only; they do not make arbitrary internet requests. |
| Disposable state | Everything lives in `instance/` (or `instance-exam/`); delete it to regenerate the database, flags, and vault. |

Command injection is intentionally real. That is why the container and the
localhost bind are the supported deployment.

---

## Flags, verification, and progress

Flags are derived from a secret:

- Guided mode: `RANGE_SECRET` environment variable, or `instance/secret.key`
  (random on first start).
- Exam mode: a fresh random secret in memory on every start. Nothing is written
  to disk and flags change between runs.

The same secret must be shared by every guided process that must agree on flags.

```bash
# Verify a flag
curl -s -X POST http://127.0.0.1:8080/api/verify \
  -H 'Content-Type: application/json' \
  -d '{"flag":"FLAG{...}"}'

# Catalog manifest (248 entries)
curl -s http://127.0.0.1:8080/api/catalog

# Progress
curl -s http://127.0.0.1:8080/api/solves
```

A successful verification records the solve and returns its vulnerability
metadata.

---

## Training agents

The range is designed so an agent can work without reading this source:

1. Give the agent the base URL (`http://127.0.0.1:8080`).
2. Optionally give it `/api/catalog` — the discovery manifest with IDs, routes,
   methods, parameters, categories, and objectives.
3. The agent probes, exploits, captures a flag, and submits it to
   `/api/verify`.
4. Score with `/api/solves`.

Included tools:

```bash
# End-to-end check: replays a working exploit for all 248 entries against a
# running instance and verifies every flag. Add RANGE_EXAM=1 for exam mode.
python tools/exploit_all.py --base http://127.0.0.1:8080

# Minimal agent client: prints the catalog and verifies a flag with the stdlib.
python tools/agent_client.py --catalog
python tools/agent_client.py --verify 'FLAG{...}'
```

For exam runs, do **not** give the agent `/api/catalog`, the Academy, the
repository, or `tools/exploit_all.py`. Give it only the base URL and have the
harness submit flags to `/api/verify`.

---

## Project layout

```
VulnWeb-Lab/
  run.py                  launcher and mode selection
  config.py               paths, secret, safe-mode switch
  app/
    catalog.py            248 vulnerability definitions + guided content
    handlers.py           vulnerable behavior, example exploits, flag verification
    site.py               realistic OrbitDesk routes and pages
    lab.py                Academy index, lessons, verification, catalog API
    store.py              SQLite seed data, solves, flags
    flags.py              deterministic flags and the flag vault
    templates/            OrbitDesk and Academy UI
    static/style.css      shared styling
  tests/
    test_catalog.py       count, uniqueness, metadata integrity
    test_exploits.py      proves every entry is exploitable
    test_exam.py          exam-mode isolation guarantees
    test_ui.py            landing, Academy, APIs
  tools/
    exploit_all.py        replay all documented exploits against a live server
    agent_client.py       minimal stdlib client for agent training
```

### Adding a family

1. Add metadata to `FAMILY_META` in `app/catalog.py`.
2. Add instance rows and `_mk(...)` calls to `_build()`.
3. Implement the handler in `app/handlers.py` and register it in `HANDLERS`.
4. Add a branch to `example_sequence()`.
5. Run `pytest` — the catalog and exploit tests enforce uniqueness and
   exploitability.

---

## Tests

```bash
# Guided mode
pytest -q
# 262 passed, 10 skipped (exam-only tests)

# Exam mode
RANGE_EXAM=1 pytest -q tests/test_catalog.py tests/test_exploits.py tests/test_exam.py
# 265 passed
```

The suite proves every one of the 248 entries is exploitable in both modes and
checks the exam-mode isolation guarantees.

---

## Ethical use

VulnWeb-Lab is for education and authorized security testing on systems you own
or are explicitly permitted to test. The vulnerabilities are deliberately
real. Do not deploy this application on a public network, and do not use the
techniques it teaches against systems without written authorization.

## License

MIT — see [LICENSE](LICENSE).
