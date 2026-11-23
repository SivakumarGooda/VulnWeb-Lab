# VulnWeb-Lab

A deliberately vulnerable web app for **learning web security** and for
**testing security scanners and AI pentest agents**.

It looks and behaves like a real product: **OrbitDesk**, a customer-support
SaaS. Hidden inside its normal features are **248 real vulnerabilities** across
**21 types** (SQL injection, XSS, SSRF, IDOR, command injection and more). Each
one hides a unique flag, so you can prove you found it.

> [!WARNING]
> **This app is insecure on purpose.** Some exercises run real shell commands
> and read real files. Run it only on your own machine, in a VM or in the
> provided container. Never put it on the internet or a shared network.

---

## Two modes

| Mode | Start it with | Use it to | What you get |
|---|---|---|---|
| **Learning** (default) | `python run.py` | Learn and practise | OrbitDesk to hack, plus the **Academy** at `/lab`: every vulnerability as a lesson with the concept, steps, hints and the fix |
| **Exam** | `python run.py --exam` | Test a scanner or AI agent | OrbitDesk only. No lessons, no answer list, and the flags change on every start |

---

## Quick start

You need Python 3.10 or newer.

**Linux / macOS / Kali**

```bash
git clone https://github.com/SivakumarGooda/VulnWeb-Lab.git
cd VulnWeb-Lab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/SivakumarGooda/VulnWeb-Lab.git
cd VulnWeb-Lab
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

Then open **http://127.0.0.1:8080** in your browser. Stop it with `Ctrl+C`.

### All start options

| Option | What it does | Default |
|---|---|---|
| `--exam` | Exam mode (see below). Without it you get learning mode | off |
| `--host <ip>` | Address to listen on | `127.0.0.1` |
| `--port <n>` | Port to listen on | `8080` |

Examples:

```bash
python run.py --port 8081           # learning mode on port 8081
python run.py --exam                # exam mode
```

Older commands still work: `--mode both` and `--mode lab` start learning mode,
`--mode site` starts exam mode.

---

## Open it from another machine

By default only the machine running the app can reach it. To use it from
another machine (for example the app runs in a Kali VM and your browser or
agent is on your laptop), tell it which address to listen on:

```bash
# Recommended: listen on one network only, using that machine's IP on it
python run.py --host 192.168.56.10 --port 8081

# Or listen on every network the machine is connected to
python run.py --host 0.0.0.0 --port 8081
```

Find the machine's IP with `ip -4 addr` (Linux) or `ipconfig` (Windows), then
open `http://<that-ip>:8081` from the other machine.

> [!CAUTION]
> Anyone who can reach that port can attack the machine running the app,
> because some exercises run **real shell commands**. Only do this on a network
> you control and nobody else uses, such as a VM host-only network. Never do it
> on home, office, café or cloud networks.
>
> - Prefer a single IP over `0.0.0.0`, which also listens on Wi-Fi and VPNs.
> - Allow only the machine that needs it, e.g.
>   `sudo ufw allow from 192.168.56.1 to any port 8081`.
> - Add `RANGE_SAFE=1` to turn off command execution and file reads if you don't
>   need those exercises.
> - Stop the app when you're done.

---

## Run with Docker

```bash
docker compose up --build
```

Open **http://127.0.0.1:8080**. The container runs as a non-root user and is
reachable from your own machine only.

- **Exam mode:** in `docker-compose.yml`, remove `RANGE_SECRET` and set
  `RANGE_EXAM: "1"`.
- **Another machine:** change the `ports:` line from `"127.0.0.1:8080:8080"` to
  your network IP (e.g. `"192.168.56.10:8080:8080"`). The caution above applies.

---

## Exam mode: testing a scanner or AI agent

Exam mode turns VulnWeb-Lab into a fair test. The tool you are testing has to
find everything on its own, like on a real target.

```bash
python run.py --exam
```

**What is hidden in exam mode**

| Learning mode | Exam mode |
|---|---|
| Academy lessons at `/lab` | Not available (404) |
| List of all vulnerabilities at `/api/catalog` | Not available (404) |
| Progress page at `/api/solves` | Not available (404) |
| Flags stay the same, stored on disk | Flags live in memory only and change on every start |

**Why one bug can't reveal the others:** each flag can only be reached through
its own vulnerability. A SQL injection reads its own database, a command
injection sees only its own flag, and so on. Breaking one challenge never
hands over the other 247.

**Not everything is linked, like a real site:**

- Most features are reachable through the normal pages and forms.
- Some API endpoints only appear in the site's JavaScript or in the developer
  docs at `/api-docs`.
- Some internal files and pages aren't linked anywhere, and have to be found by
  guessing or with wordlists. `robots.txt` leaks a few of them.
- You only ever see your own record IDs; finding other people's data means
  changing IDs yourself.
- `robots.txt` disallows `/admin/`. Tools that respect robots.txt will skip the
  admin area unless told otherwise.

**How to run a fair test**

1. Run the app in a fresh container or VM, and the tool on a different machine.
2. Give the tool **only the base URL**, never this repository, `/api/catalog`,
   the Academy or `tools/exploit_all.py` (they contain the answers).
3. Delete any leftover `instance/` folder from earlier learning sessions first.
4. Score by checking the flags the tool finds (see below).

---

## Checking flags

Every flag looks like `FLAG{orbit_<id>_<token>}`. Check one with:

```bash
curl -s -X POST http://127.0.0.1:8080/api/verify \
  -H 'Content-Type: application/json' \
  -d '{"flag":"FLAG{...}"}'
```

A correct flag returns which vulnerability it belongs to and records it as
solved. You can also paste flags into the Academy.

Learning mode only:

```bash
curl -s http://127.0.0.1:8080/api/catalog   # all 248 vulnerabilities
curl -s http://127.0.0.1:8080/api/solves    # what you've solved so far
```

**About flag values:** in learning mode, flags come from a random secret
stored in `instance/secret.key`, so they stay the same between restarts (set
`RANGE_SECRET` to share one secret between machines). In exam mode they change
every time.

---

## What's inside

| Type | Count | Examples |
|---|---:|---|
| SQL injection (`sqli`) | 24 | Login bypass, UNION extraction, filters that strip spaces |
| Reflected XSS (`xss`) | 24 | HTML, attribute, JavaScript, URL and JSON contexts |
| Stored XSS (`stored-xss`) | 12 | Comments, profiles, reviews, wiki pages |
| Command injection (`cmdi`) | 16 | Ping, DNS, whois and file-conversion tools |
| Path traversal (`traversal`) | 16 | File downloads, previews, `....//` filter bypasses |
| SSRF (`ssrf`) | 14 | Webhooks, URL previews, allowlist and IP-encoding bypasses |
| IDOR (`idor`) | 20 | Other customers' tickets, invoices, files and payments |
| Authentication (`auth`) | 16 | Default passwords, guessable reset tokens, weak JWTs, 2FA bypass |
| Open redirect (`redirect`) | 12 | Login and logout redirects, prefix-check bypasses |
| Template injection (`ssti`) | 12 | Email and report templates |
| File upload (`upload`) | 10 | HTML/SVG uploads, fake content types, zip-slip |
| Business logic (`logic`) | 16 | Negative quantities, price tampering, coupon stacking, races |
| Misconfiguration (`info`) | 20 | Exposed `.env`/`.git`/backups, CORS, missing headers, CSRF, CRLF |
| NoSQL injection (`nosql`) | 6 | `$ne`, `$regex`, `$or` login bypasses |
| LDAP injection (`ldap`) | 4 | Directory search and directory sign-in |
| XXE (`xxe`) | 6 | XML imports that read local files |
| Host header (`host-header`) | 4 | Poisoned password-reset and invitation links |
| Parameter pollution (`hpp`) | 4 | Repeated parameters that flip a decision |
| Cache poisoning (`cache`) | 4 | Cached pages that reflect a forwarded host |
| CSV injection (`csv-injection`) | 4 | Spreadsheet formulas in CSV exports |
| Email header injection (`email-injection`) | 4 | Extra `Bcc:` headers in contact and invite forms |
| **Total** | **248** | |

---

## Safety settings

| Setting | What it does |
|---|---|
| `RANGE_HOST` / `--host` | Address to listen on. Default `127.0.0.1` (this machine only). |
| `RANGE_PORT` / `--port` | Port. Default `8080`. |
| `RANGE_SAFE=1` | Turns off command execution, file reads and `file://` fetches. |
| `RANGE_EXAM=1` / `--exam` | Exam mode. |
| `RANGE_SECRET` | Fixed secret for stable flags in learning mode. |

Also built in:

- The SSRF exercises only reach fake internal services. They never fetch
  arbitrary internet addresses.
- All data lives in `instance/` (or `instance-exam/`). Delete the folder to reset
  everything: database, flags and solves.

---

## For developers

### Run the tests

```bash
pytest -q                                   # learning mode: 296 passed, 11 skipped
RANGE_EXAM=1 pytest -q tests/test_catalog.py tests/test_exploits.py \
  tests/test_exam.py tests/test_product.py  # exam mode: 292 passed, 8 skipped
```

The tests prove every one of the 248 vulnerabilities can actually be exploited
in both modes. They also check that exam mode keeps answers hidden, and that
the site stays realistic: no hint words on product pages, and internal pages
stay unlinked.

To check a running instance end to end:

```bash
python tools/exploit_all.py --base http://127.0.0.1:8080              # learning mode
RANGE_EXAM=1 python tools/exploit_all.py --base http://127.0.0.1:8080 # exam mode
```

### Project layout

```
VulnWeb-Lab/
  run.py                start-up options (learning or --exam)
  config.py             paths, secret, safe mode, exam mode
  app/
    catalog.py          the 248 vulnerabilities and their lessons
    handlers.py         the vulnerable behaviour and example exploits
    product.py          OrbitDesk pages, navigation, robots.txt, sitemap
    site.py             OrbitDesk routes
    lab.py              the Academy and the catalog API
    store.py            database, flags and solves
    flags.py            flag generation
    templates/          page templates and the app's JavaScript (app.js)
    static/style.css    styling
  tests/
    test_catalog.py     every entry is complete and unique
    test_exploits.py    every entry is exploitable
    test_exam.py        exam mode hides the answers
    test_product.py     the site stays realistic
    test_ui.py          Academy and API pages
  tools/
    exploit_all.py      replays every exploit against a running instance
    agent_client.py     minimal client for agents: list the catalog, check flags
```

### Adding a new vulnerability type

1. Describe it in `FAMILY_META` in `app/catalog.py`.
2. Add its entries in `_build()` in the same file.
3. Write its handler in `app/handlers.py` and add it to `HANDLERS`.
4. Add a working example exploit in `example_sequence()`.
5. Place the feature somewhere natural in OrbitDesk (`app/product.py`), using
   normal product wording.
6. Run `pytest`. The tests will tell you if anything is missing.

---

## Ethical use

Use VulnWeb-Lab only to learn, and to test tools on systems you own or have
written permission to test. Never use what it teaches against anyone else's
systems.

## License

MIT. See [LICENSE](LICENSE).
