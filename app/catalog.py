"""The vulnerability catalog.

Each entry is a real, individually flagged vulnerability instance. ``extra``
holds the knobs a family handler needs (mode, filter, context, kind, ...).
Guided-lab content lives alongside the metadata so the Academy and the live
OrbitDesk site can never drift apart.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Vuln:
    id: str
    family: str
    title: str
    category: str
    cwe: str
    owasp: str
    difficulty: str
    route: str
    method: str
    param: str
    summary: str
    concept: str
    objective: str
    steps: tuple[str, ...]
    hints: tuple[str, ...]
    remediation: str
    extra: dict[str, Any] = field(default_factory=dict)


FAMILY_META: dict[str, dict[str, Any]] = {
    "sqli": {
        "category": "Injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "concept": (
            "SQL injection happens when user input is concatenated into a query instead of "
            "being sent as a bound parameter. The database then treats part of the input as SQL "
            "syntax, so an attacker can change the query's meaning - bypass a login, read other "
            "tables, or extract secrets."
        ),
        "objective": "Make the {title} endpoint return a row it should not, then capture the flag.",
        "steps": (
            "Send a normal value first and note the response shape.",
            "Add a single quote to see whether a SQL error appears (syntax feedback).",
            "Build a boolean bypass such as ' OR 1=1-- for a login, or a UNION for a search.",
            "Use the flags table (vuln_id, flag) for UNION payloads, then submit the flag.",
        ),
        "hints": (
            "The query is built by string concatenation.",
            "For a login form, comment out the password check with --.",
            "Search endpoints often accept UNION SELECT with two columns.",
            "The flags table is the easiest place to read the proof value.",
        ),
        "remediation": (
            "Use parameterized queries / prepared statements. Never concatenate input into SQL, "
            "restrict database privileges, and return generic errors."
        ),
    },
    "xss": {
        "category": "Cross-site Scripting",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "concept": (
            "Reflected XSS occurs when the application writes user input into an HTML page "
            "without context-aware encoding. If the input can break out of its context and add "
            "markup or script, an attacker can execute JavaScript in a victim's browser."
        ),
        "objective": "Get executable markup reflected by {title}, then capture the flag.",
        "steps": (
            "Identify the reflection context: HTML body, attribute value, JavaScript string, or URL.",
            "Send a harmless marker such as RADIANT to confirm the reflection.",
            "Break out of the context with the correct quote or tag, then add an event handler.",
            "If a filter blocks a keyword, use an equivalent tag, handler, or encoding.",
        ),
        "hints": (
            "View the page source to see exactly where your value lands.",
            "Attribute values usually need a leading quote to escape.",
            "If <script> is blocked, try <img src=x onerror=...> or <svg onload=...>.",
            "If alert is blocked, use confirm or prompt instead.",
        ),
        "remediation": (
            "HTML-encode output in the correct context, use a templating engine with autoescaping, "
            "and add a Content-Security-Policy."
        ),
    },
    "stored-xss": {
        "category": "Cross-site Scripting",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "concept": (
            "Stored XSS saves attacker-controlled markup and serves it to every later visitor. "
            "It is more dangerous than reflected XSS because the payload persists and can hit "
            "other users, including administrators."
        ),
        "objective": "Persist executable markup through {title}, then load the page again to trigger it.",
        "steps": (
            "Submit a unique marker and find where it is rendered.",
            "Determine whether the stored value is encoded on output or only filtered on input.",
            "Store a payload that survives the input filter and executes in the output context.",
            "Reload the listing/detail page to trigger the stored content.",
        ),
        "hints": (
            "Input filters are usually weaker than output encoding.",
            "Try a different tag if script tags are stripped.",
            "The payload must survive the round trip through the database.",
        ),
        "remediation": (
            "Encode on output, validate on input, sanitize rich text with a real allowlist "
            "sanitizer, and use a strict CSP."
        ),
    },
    "cmdi": {
        "category": "Injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "concept": (
            "OS command injection occurs when input is passed to a shell. Shell metacharacters "
            "(; & | $() backticks) let an attacker append a second command that runs with the "
            "web application's privileges."
        ),
        "objective": "Append a command to {title} that reads the per-vulnerability flag file.",
        "steps": (
            "Confirm the feature runs an operating-system command.",
            "Try a harmless separator such as ; or & followed by a simple command.",
            "Read the flag file from the instance/vault directory.",
            "On Windows use & and type; on Linux use ; and cat.",
        ),
        "hints": (
            "The output you see is the command's stdout.",
            "The lab page shows the exact vault path for this instance.",
            "If the first separator is blocked, try &&, |, or $()." ,
        ),
        "remediation": (
            "Avoid the shell entirely; use an argument list API. If a shell is unavoidable, "
            "strictly allowlist input, escape it, and run with least privilege."
        ),
    },
    "traversal": {
        "category": "File Access",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "concept": (
            "Path traversal lets a user escape an intended directory with ../ sequences. "
            "If the resulting path is used to read a file, the attacker can reach configuration, "
            "credentials, or other tenants' data."
        ),
        "objective": "Escape the download directory in {title} and read this vulnerability's flag file.",
        "steps": (
            "Request a normal file and note the base directory.",
            "Add ../ segments to walk upward.",
            "If ../ is stripped, try ....// or URL-encode the dots and slashes.",
            "Read ../vault/<vuln-id>.txt and submit the flag.",
        ),
        "hints": (
            "Filters that remove ../ once can often be bypassed with ....//.",
            "Try percent-encoding, including double-encoding.",
            "The vault is one level above the files directory.",
        ),
        "remediation": (
            "Resolve the final path and verify it stays inside the intended directory. Avoid "
            "user-controlled paths; map opaque IDs to files instead."
        ),
    },
    "ssrf": {
        "category": "Server-Side Request Forgery",
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "concept": (
            "SSRF occurs when the server fetches a URL supplied by the user. An attacker can point "
            "it at loopback, internal services, or cloud metadata endpoints that the attacker "
            "cannot reach directly."
        ),
        "objective": "Make {title} fetch the internal metadata endpoint for this vulnerability.",
        "steps": (
            "Confirm that the server performs the request (look for fetched content).",
            "Try loopback addresses and internal service names.",
            "Bypass naive allowlists with userinfo (trusted.com@127.0.0.1) or alternate IP forms.",
            "Read the flag from the returned metadata JSON.",
        ),
        "hints": (
            "127.0.0.1, localhost, and [::1] are common internal targets.",
            "Decimal 2130706433 and hex 0x7f000001 both mean 127.0.0.1.",
            "URL parsers treat http://trusted.com@127.0.0.1 as host 127.0.0.1.",
        ),
        "remediation": (
            "Allowlist destinations, resolve names and validate the resolved IP, block private "
            "and link-local ranges, disable redirects, and isolate egress."
        ),
    },
    "idor": {
        "category": "Broken Access Control",
        "cwe": "CWE-639",
        "owasp": "A01:2021 - Broken Access Control",
        "concept": (
            "Insecure Direct Object Reference / BOLA means an object is fetched by an identifier "
            "without checking that the caller owns or may access it. Changing the ID returns "
            "another tenant's record."
        ),
        "objective": "Retrieve a record you do not own from {title} and capture its flag.",
        "steps": (
            "Find the identifier used by the endpoint.",
            "Request your own-looking ID first, then change it to a neighbouring value.",
            "Try both numeric and opaque identifiers if the endpoint accepts them.",
            "The response belongs to another tenant and contains the flag.",
        ),
        "hints": (
            "Object IDs are often sequential.",
            "Authentication without authorization is the bug.",
            "Tenant boundaries must be enforced server-side on every object access.",
        ),
        "remediation": (
            "Enforce object-level authorization on every request, scope queries by the caller's "
            "tenant and subject, and prefer unguessable IDs as defence in depth."
        ),
    },
    "auth": {
        "category": "Authentication & Session",
        "cwe": "CWE-287",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "concept": (
            "Authentication flaws let a user become someone else: default credentials, predictable "
            "tokens, unsigned JWTs, client-side role flags, or a 2FA step that trusts a request "
            "parameter. The result is a session or token with admin rights."
        ),
        "objective": "Become an administrator or otherwise satisfy {title}, then capture the flag.",
        "steps": (
            "Inspect the login, reset, cookie, or token flow and identify what the server trusts.",
            "Look for client-controlled role, algorithm, or verification fields.",
            "Forge or replay the value the server should have validated.",
            "Use the resulting admin context to obtain the flag.",
        ),
        "hints": (
            "Try the classic default credential pairs first.",
            "Decode cookies and JWTs; they are often only encoded, not protected.",
            "If an algorithm can be 'none', the signature is irrelevant.",
            "Weak HMAC secrets are often short dictionary words.",
        ),
        "remediation": (
            "Use a proven identity library, strong password hashing, server-side session state, "
            "signed and verified tokens with modern algorithms, and enforce 2FA server-side."
        ),
    },
    "redirect": {
        "category": "Open Redirect",
        "cwe": "CWE-601",
        "owasp": "A01:2021 - Broken Access Control",
        "concept": (
            "An open redirect takes a destination from the request and sends the user there after "
            "a trusted action. Attackers use it for phishing and to bypass allowlists in OAuth "
            "or SSO flows."
        ),
        "objective": "Make {title} redirect to an attacker-controlled host and capture the flag.",
        "steps": (
            "Find the parameter that controls the post-action destination.",
            "Send an external URL and inspect the Location header.",
            "If an allowlist exists, try a lookalike host or userinfo trick.",
            "The range returns the proof flag in X-Range-Flag on success.",
        ),
        "hints": (
            "https://trusted.com.evil.test passes a prefix check for trusted.com.",
            "Protocol-relative //evil.test is another common bypass.",
            "javascript: destinations are especially dangerous.",
        ),
        "remediation": (
            "Only redirect to relative paths or an exact allowlist of hosts. Validate after "
            "parsing and never trust prefix matching."
        ),
    },
    "ssti": {
        "category": "Template Injection",
        "cwe": "CWE-1336",
        "owasp": "A03:2021 - Injection",
        "concept": (
            "Server-side template injection happens when user input is compiled as a template "
            "instead of passed in as data. The attacker can read template context variables and, "
            "in unsandboxed engines, reach the underlying runtime."
        ),
        "objective": "Evaluate template syntax in {title} and read the flag from the template context.",
        "steps": (
            "Send a literal {{ 7*7 }} style probe and look for 49 in the output.",
            "If double braces are filtered, try statement blocks or alternate syntax.",
            "Read the settings.FLAG value from the template context.",
            "Submit the rendered flag.",
        ),
        "hints": (
            "The range renders your input with a Jinja sandbox.",
            "settings is a dict exposed to the template.",
            "{% print(settings.FLAG) %} works when {{ }} is blocked.",
        ),
        "remediation": (
            "Never compile user input as a template. Use fixed templates and pass untrusted values "
            "as data; use a sandbox only as defence in depth."
        ),
    },
    "upload": {
        "category": "File Upload",
        "cwe": "CWE-434",
        "owasp": "A04:2021 - Insecure Design",
        "concept": (
            "Unrestricted file upload lets an attacker store executable or active content "
            "(HTML, SVG, scripts), traverse out of the upload directory, overwrite files, or "
            "smuggle archives that escape on extraction."
        ),
        "objective": "Abuse {title} to store or place active content / escape the upload directory.",
        "steps": (
            "Upload a harmless file and observe how the name, type, and content are handled.",
            "Try an active content type such as HTML or SVG.",
            "Try a double extension, a spoofed Content-Type, or a traversal filename.",
            "For archives, include an entry that extracts outside the target directory.",
        ),
        "hints": (
            "Checking only the extension is not enough; check content and serve safely.",
            "A .jpg.html name often slips past extension allowlists.",
            "SVG is XML and can carry onload handlers.",
        ),
        "remediation": (
            "Allowlist types by verified content, generate server-side names, store outside the "
            "web root, serve with a safe Content-Type and Content-Disposition, and limit size."
        ),
    },
    "logic": {
        "category": "Business Logic",
        "cwe": "CWE-840",
        "owasp": "A04:2021 - Insecure Design",
        "concept": (
            "Business-logic flaws are valid requests used in unintended ways: negative quantities, "
            "client-supplied prices, stacked coupons, skipped workflow steps, or replayed actions. "
            "No injection is needed - the rules themselves are wrong."
        ),
        "objective": "Break the intended business rule in {title} and capture the flag.",
        "steps": (
            "Understand the rule the feature is supposed to enforce.",
            "Send values the UI would never send (negative, zero, huge, or replayed).",
            "Watch for state changes that should be impossible.",
            "Trigger the success condition described in the lab page.",
        ),
        "hints": (
            "The UI is not the security boundary.",
            "Try negative amounts and quantities.",
            "Replay the same action twice and compare the result.",
        ),
        "remediation": (
            "Model the rules server-side, validate ranges and invariants, make state transitions "
            "atomic, and never trust prices, roles, or totals from the client."
        ),
    },
    "info": {
        "category": "Security Misconfiguration",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "concept": (
            "Misconfigurations leak more than data: debug endpoints, backups, CORS that reflects "
            "any origin with credentials, missing security headers, CSRF-free state changes, and "
            "CRLF injection into response headers."
        ),
        "objective": "Exploit the configuration weakness in {title} and capture the flag.",
        "steps": (
            "Enumerate the endpoint and the headers it returns.",
            "For CORS, send an attacker Origin and check the Access-Control-Allow-* headers.",
            "For CSRF, send a state-changing request with an external Origin and no token.",
            "For CRLF, inject %0d%0a into a value that reaches a response header.",
        ),
        "hints": (
            "Reflected Origin plus Allow-Credentials is the dangerous CORS pattern.",
            "Security headers are only useful if they are present on every response.",
            "Passive findings expose X-Range-Flag when you send X-Range-Audit: 1.",
        ),
        "remediation": (
            "Disable debug/backup endpoints in production, use an explicit CORS allowlist, add "
            "CSP/HSTS/X-Frame-Options, require CSRF tokens, and reject header control characters."
        ),
    },
    "nosql": {
        "category": "Injection",
        "cwe": "CWE-943",
        "owasp": "A03:2021 - Injection",
        "concept": (
            "NoSQL injection abuses query operators. If a JSON body is passed straight into a "
            "document query, values like {\"$ne\": null} or {\"$regex\": \".*\"} change the "
            "predicate and bypass authentication."
        ),
        "objective": "Use a query operator to bypass {title} and capture the flag.",
        "steps": (
            "Confirm the endpoint accepts JSON.",
            "Replace a scalar value with an operator object.",
            "Try $ne, $gt, $regex, $in, or $or.",
            "When the query matches the admin record, the flag is returned.",
        ),
        "hints": (
            "{\"$ne\": null} matches any value that is not null.",
            "{\"$regex\": \".*\"} matches every string.",
            "$or lets you supply alternative predicates.",
        ),
        "remediation": (
            "Validate and type-check input, reject keys starting with $, use a schema, and apply "
            "least-privilege database roles."
        ),
    },
    "ldap": {
        "category": "Injection",
        "cwe": "CWE-90",
        "owasp": "A03:2021 - Injection",
        "concept": (
            "LDAP injection inserts filter metacharacters into a directory query. A payload such "
            "as *)(uid=* can turn a specific user lookup into a match-anything filter, bypassing "
            "authentication or exposing directory entries."
        ),
        "objective": "Bypass the directory lookup in {title} and capture the flag.",
        "steps": (
            "Confirm the input is placed inside an LDAP filter.",
            "Try wildcard and filter-termination characters.",
            "Aim for a filter that matches the admin entry.",
            "The flag is returned when the admin record is matched.",
        ),
        "hints": (
            "LDAP filters use &, |, and ! with parentheses.",
            "A bare * is a wildcard.",
            "Breaking out of the value with )( is the classic bypass.",
        ),
        "remediation": (
            "Escape LDAP filter metacharacters, use parameterized directory APIs, and avoid "
            "building filters from raw input."
        ),
    },
    "xxe": {
        "category": "XML External Entity",
        "cwe": "CWE-611",
        "owasp": "A05:2021 - Security Misconfiguration",
        "concept": (
            "XML External Entity (XXE) attacks abuse a parser that resolves external entities. "
            "A DOCTYPE can define an entity pointing at a local file or an internal URL; when "
            "the parser expands it, the file contents or server response appear in the output."
        ),
        "objective": "Use an external entity in {title} to read this challenge's flag.",
        "steps": (
            "Confirm the endpoint parses XML and reflects a parsed value.",
            "Add a DOCTYPE that declares an entity with a file:// SYSTEM identifier.",
            "Reference the entity in the document body.",
            "Read the returned entity value and submit the flag.",
        ),
        "hints": (
            "The parser resolves external general entities.",
            "The flag lives in the instance vault (the lab page shows the path).",
            "If the body is not reflected, reference the entity inside a parsed element.",
        ),
        "remediation": (
            "Disable DTDs and external entity resolution, use a hardened XML parser, and never "
            "pass untrusted XML to a parser that resolves entities."
        ),
    },
    "host-header": {
        "category": "HTTP Header Injection",
        "cwe": "CWE-644",
        "owasp": "A05:2021 - Security Misconfiguration",
        "concept": (
            "Host header injection occurs when an application builds absolute links from the "
            "request Host header without validating it. An attacker can make password-reset or "
            "invitation links point at their own domain."
        ),
        "objective": "Poison the link generated by {title} with an attacker-controlled host.",
        "steps": (
            "Trigger the feature and inspect the absolute URL it generates.",
            "Change the Host header (or X-Forwarded-Host) to an external domain.",
            "Observe the generated link now points at that domain.",
            "The flag is returned when the poisoned host is accepted.",
        ),
        "hints": (
            "Absolute URLs are often built from request.host.",
            "X-Forwarded-Host is trusted by many frameworks and proxies.",
            "Use a hostname such as evil.test in the header.",
        ),
        "remediation": (
            "Use a configured canonical host for links, validate Host against an allowlist, and "
            "never trust forwarded host headers from untrusted clients."
        ),
    },
    "hpp": {
        "category": "HTTP Parameter Pollution",
        "cwe": "CWE-20",
        "owasp": "A04:2021 - Insecure Design",
        "concept": (
            "HTTP parameter pollution sends the same parameter more than once. Different layers "
            "(framework, application, proxy, downstream service) pick different values - first, "
            "last, or a concatenation - so a benign-looking duplicate can change an authorization "
            "or business decision."
        ),
        "objective": "Use duplicate parameters to change the privileged decision in {title}.",
        "steps": (
            "Send the parameter once and note the normal behaviour.",
            "Send it twice with a normal value and a privileged value.",
            "Observe which copy the server trusts.",
            "The flag is returned when the privileged value wins.",
        ),
        "hints": (
            "Send the same name in multiple query parameters.",
            "Try both orders: normal then privileged, and the reverse.",
            "Some frameworks expose getlist/allvalues for duplicates.",
        ),
        "remediation": (
            "Reject unexpected duplicate parameters, parse the raw query consistently, and make "
            "authorization decisions server-side from a single validated value."
        ),
    },
    "cache": {
        "category": "Web Cache Poisoning",
        "cwe": "CWE-349",
        "owasp": "A05:2021 - Security Misconfiguration",
        "concept": (
            "Web cache poisoning occurs when an intermediary caches a response keyed only on the "
            "URL while the response depends on a header the attacker controls, such as "
            "X-Forwarded-Host. The poisoned response is then served to other users."
        ),
        "objective": "Poison the cached response of {title} through a request header.",
        "steps": (
            "Request the page and note the cache headers.",
            "Send a request with X-Forwarded-Host set to an attacker domain.",
            "Observe the value reflected into the cached body.",
            "The flag is returned when the header reaches the cached response.",
        ),
        "hints": (
            "Caches often ignore host-related headers when building the cache key.",
            "Look for X-Cache: HIT in the response.",
            "The reflected value appears in generated links or script.",
        ),
        "remediation": (
            "Include every input that affects the response in the cache key, normalise headers, "
            "and do not reflect unvalidated host values into cached content."
        ),
    },
    "csv-injection": {
        "category": "CSV Injection",
        "cwe": "CWE-1236",
        "owasp": "A03:2021 - Injection",
        "concept": (
            "CSV/formula injection stores a value beginning with =, +, -, or @ in an exported "
            "spreadsheet. When a user opens the file, the spreadsheet evaluates it as a formula, "
            "which can leak data or run commands."
        ),
        "objective": "Inject a spreadsheet formula into the export from {title}.",
        "steps": (
            "Export the report and note which fields you control.",
            "Put a value beginning with =, +, - or @ into a field.",
            "Request the export and inspect the CSV.",
            "The flag is returned when a dangerous formula prefix is exported.",
        ),
        "hints": (
            "Spreadsheet software treats a leading = as a formula.",
            "+ and @ are also risky prefixes.",
            "Quoting or escaping the cell prevents evaluation.",
        ),
        "remediation": (
            "Prefix user-controlled cells with a single quote, escape formula characters, and "
            "warn users before opening exported spreadsheets."
        ),
    },
    "email-injection": {
        "category": "Email Header Injection",
        "cwe": "CWE-93",
        "owasp": "A03:2021 - Injection",
        "concept": (
            "Email header injection inserts CR/LF characters into a value that is placed in a "
            "message header. The injected line becomes an extra header such as Bcc or Cc, letting "
            "an attacker redirect or copy the message."
        ),
        "objective": "Inject an extra header through {title} and capture the flag.",
        "steps": (
            "Find the field that becomes an email header.",
            "Include a carriage-return/line-feed sequence followed by Bcc: or Cc:.",
            "Submit the form and inspect the generated headers.",
            "The flag is returned when the injected header is accepted.",
        ),
        "hints": (
            "CRLF is represented by %0d%0a in a URL-encoded body.",
            "Try Bcc: victim@example.test after the newline.",
            "Input validation should reject control characters.",
        ),
        "remediation": (
            "Reject CR/LF and control characters in header values, use a mail library that "
            "encodes headers safely, and validate addresses strictly."
        ),
    },
}

FAMILIES = tuple(FAMILY_META)


def _mk(family: str, idx: int, title: str, route: str, method: str, param: str,
        extra: dict[str, Any] | None = None, difficulty: str | None = None) -> Vuln:
    meta = FAMILY_META[family]
    if difficulty is None:
        difficulty = "medium" if extra and extra.get("filter") not in (None, "none") else "easy"
    return Vuln(
        id=f"{family}-{idx:02d}",
        family=family,
        title=title,
        category=meta["category"],
        cwe=meta["cwe"],
        owasp=meta["owasp"],
        difficulty=difficulty,
        route=route,
        method=method,
        param=param,
        summary=f"{title} - {meta['category']} ({meta['cwe']}).",
        concept=meta["concept"],
        objective=meta["objective"].format(title=title),
        steps=tuple(meta["steps"]),
        hints=tuple(meta["hints"]),
        remediation=meta["remediation"],
        extra=dict(extra or {}),
    )


def _build() -> list[Vuln]:
    out: list[Vuln] = []

    # ---------------------------------------------------------------- SQLi (24)
    sqli = [
        ("Sign-in form", "/auth/login", "POST", "email", "login", "none"),
        ("Legacy sign-in", "/auth/login-legacy", "POST", "email", "login", "strip_spaces"),
        ("Admin sign-in", "/auth/admin", "POST", "username", "login", "none"),
        ("Staff sign-in", "/auth/staff", "POST", "email", "login", "none"),
        ("Ticket search API", "/api/v1/tickets/search", "GET", "q", "union", "none"),
        ("Ticket list API v2", "/api/v2/tickets", "GET", "q", "union", "strip_spaces"),
        ("Product catalog", "/shop/products", "GET", "category", "union", "none"),
        ("Report filter", "/reports/filter", "GET", "owner", "union", "numeric"),
        ("Admin user search", "/admin/users", "GET", "q", "union", "none"),
        ("Team directory", "/team/members", "GET", "q", "union", "strip_spaces"),
        ("Support search", "/support/search", "GET", "q", "union", "none"),
        ("Invoice lookup", "/billing/invoices", "GET", "id", "union", "numeric"),
        ("Asset search", "/assets/search", "GET", "q", "union", "none"),
        ("Audit log filter", "/audit/logs", "GET", "actor", "union", "strip_spaces"),
        ("Integration search", "/integrations/search", "GET", "q", "union", "none"),
        ("File search", "/files/search", "GET", "name", "union", "numeric"),
        ("Customer search", "/customers", "GET", "q", "union", "none"),
        ("Order lookup", "/orders", "GET", "id", "union", "strip_spaces"),
        ("Orders API v3", "/api/v3/orders", "GET", "ref", "union", "none"),
        ("Knowledge search", "/knowledge/search", "GET", "q", "union", "numeric"),
        ("Status filter", "/status/filter", "GET", "state", "union", "none"),
        ("Export preview", "/exports/preview", "GET", "table", "union", "strip_spaces"),
        ("Dashboard widget", "/dashboard/widgets", "GET", "widget", "union", "none"),
        ("Notification lookup", "/notifications", "GET", "id", "union", "numeric"),
    ]
    for i, (title, route, method, param, mode, filt) in enumerate(sqli, 1):
        out.append(_mk("sqli", i, title, route, method, param,
                       {"mode": mode, "filter": filt}))

    # --------------------------------------------------------- Reflected XSS (24)
    xss = [
        ("Site search", "/search", "q", "html", "none"),
        ("Product filter", "/products", "name", "html", "strip_script"),
        ("Support search", "/support", "query", "html", "block_onerror"),
        ("Help center search", "/help/search", "q", "html", "block_alert"),
        ("Status page message", "/status", "msg", "html", "none"),
        ("Event title", "/events", "title", "title", "none"),
        ("Profile display name", "/profile", "name", "attr_d", "none"),
        ("Settings tab", "/settings", "tab", "attr_d", "strip_script"),
        ("Team invitation", "/invite", "email", "attr_s", "none"),
        ("Cart note", "/cart", "note", "textarea", "none"),
        ("Feedback form", "/feedback", "text", "html", "none"),
        ("Comment preview", "/comments", "text", "html", "strip_script"),
        ("Blog slug", "/blog", "slug", "href", "none"),
        ("Download link", "/downloads", "file", "href", "none"),
        ("Advanced search", "/search/advanced", "q", "js_s", "none"),
        ("API preview", "/api/preview", "q", "json", "none"),
        ("Documentation preview", "/docs", "page", "markdown", "none"),
        ("Widget name", "/widgets", "name", "attr_u", "none"),
        ("Notification preview", "/notifications/preview", "msg", "js_d", "none"),
        ("Report share title", "/reports/share", "title", "attr_u", "strip_quotes"),
        ("Team invite display", "/team/invite", "name", "attr_u", "none"),
        ("Integration callback", "/integrations/callback", "state", "html", "none"),
        ("Knowledge article", "/knowledge/article", "q", "html", "none"),
        ("Admin audit note", "/admin/audit", "note", "html", "strip_script"),
    ]
    for i, (title, route, param, ctx, filt) in enumerate(xss, 1):
        out.append(_mk("xss", i, title, route, "GET", param,
                       {"context": ctx, "filter": filt}))

    # ------------------------------------------------------------- Stored XSS (12)
    stored = [
        ("Ticket comment", "/tickets/comments", "html", "none"),
        ("Customer note", "/customers/notes", "html", "strip_script"),
        ("Profile bio", "/profile/bio", "html", "none"),
        ("Product review", "/reviews", "html", "block_onerror"),
        ("Support reply", "/support/reply", "html", "strip_script"),
        ("Team wiki", "/wiki", "markdown", "none"),
        ("Status update", "/status/update", "html", "none"),
        ("File description", "/files/description", "html", "none"),
        ("Invitation message", "/invitations", "html", "none"),
        ("Email signature", "/signature", "html", "none"),
        ("Dashboard announcement", "/dashboard/announcements", "html", "none"),
        ("Knowledge feedback", "/knowledge/feedback", "html", "none"),
    ]
    for i, (title, route, ctx, filt) in enumerate(stored, 1):
        out.append(_mk("stored-xss", i, title, route, "GET", "content",
                       {"context": ctx, "filter": filt}))

    # --------------------------------------------------------- Command injection (16)
    cmdi = [
        ("Ping utility", "/tools/ping", "host", "ping -c 1 "),
        ("DNS lookup", "/tools/dns", "host", "nslookup "),
        ("Whois lookup", "/tools/whois", "domain", "whois "),
        ("URL fetcher", "/tools/curl", "url", "curl -s "),
        ("Image converter", "/tools/convert", "file", "convert "),
        ("Archive creator", "/tools/archive", "dir", "tar czf /tmp/range.tgz "),
        ("Git remote check", "/tools/git", "url", "git ls-remote "),
        ("Media probe", "/tools/media", "file", "ffmpeg -i "),
        ("DNS dig", "/tools/dig", "host", "dig "),
        ("Traceroute", "/tools/trace", "host", "traceroute "),
        ("TLS check", "/tools/tls", "host", "openssl s_client -connect "),
        ("Zip utility", "/tools/zip", "dir", "zip -r /tmp/range.zip "),
        ("Page fetcher", "/tools/fetch", "url", "wget -qO- "),
        ("IPv6 ping", "/tools/ping6", "host", "ping6 -c 1 "),
        ("Host lookup", "/tools/host", "domain", "host "),
        ("Port probe", "/tools/port", "host", "nc -zv "),
    ]
    for i, (title, route, param, prefix) in enumerate(cmdi, 1):
        out.append(_mk("cmdi", i, title, route, "GET", param,
                       {"prefix": prefix}, difficulty="medium"))

    # ------------------------------------------------------------ Path traversal (16)
    trav = [
        ("Attachment download", "/files/download", "file", "none"),
        ("Attachment preview", "/files/preview", "file", "strip_dotdot"),
        ("Report download", "/reports/download", "name", "none"),
        ("Export download", "/exports/download", "path", "strip_dotdot"),
        ("Document viewer", "/documents/view", "doc", "none"),
        ("Attachment get", "/attachments/get", "id", "none"),
        ("Backup download", "/backup/download", "file", "none"),
        ("Template viewer", "/templates/view", "name", "none"),
        ("Log viewer", "/logs/view", "file", "none"),
        ("Media viewer", "/media/image", "path", "none"),
        ("Certificate download", "/certificates/download", "name", "none"),
        ("Invoice PDF", "/invoices/pdf", "invoice", "none"),
        ("Statement download", "/statements/download", "file", "strip_dotdot"),
        ("Asset file", "/assets/file", "name", "strip_dotdot"),
        ("Uploaded file", "/uploads/get", "filename", "none"),
        ("Archive entry", "/archive/entry", "path", "none"),
    ]
    for i, (title, route, param, filt) in enumerate(trav, 1):
        out.append(_mk("traversal", i, title, route, "GET", param,
                       {"filter": filt}))

    # ------------------------------------------------------------------ SSRF (14)
    ssrf = [
        ("Webhook tester", "/integrations/webhook/test", "url", "none"),
        ("Report importer", "/reports/import", "source", "allow_trusted"),
        ("Image proxy", "/images/proxy", "src", "block_local"),
        ("Link preview", "/api/link-preview", "url", "none"),
        ("Feed validator", "/feeds/validate", "url", "allow_trusted"),
        ("Admin URL checker", "/admin/url-check", "url", "block_local"),
        ("Avatar importer", "/support/avatar", "avatar_url", "none"),
        ("Webhook delivery", "/webhooks/deliver", "endpoint", "allow_trusted"),
        ("PDF renderer", "/pdf/render", "html_url", "none"),
        ("Screenshot service", "/screenshots", "url", "block_local"),
        ("RSS preview", "/rss/preview", "feed", "none"),
        ("Generic fetch API", "/api/fetch", "target", "none"),
        ("URL monitor", "/monitor/check", "url", "none"),
        ("Remote backup", "/backup/remote", "remote", "none"),
    ]
    for i, (title, route, param, filt) in enumerate(ssrf, 1):
        out.append(_mk("ssrf", i, title, route, "GET", param,
                       {"filter": filt, "rid": 7000 + i}, difficulty="medium"))

    # ------------------------------------------------------------------ IDOR (20)
    idor = [
        ("Ticket detail", "/api/tickets/<int:rid>", "ticket"),
        ("Ticket detail v1", "/api/v1/tickets/<int:rid>", "ticket"),
        ("Invoice detail", "/api/invoices/<int:rid>", "invoice"),
        ("User profile", "/api/users/<int:rid>", "user"),
        ("File metadata", "/api/files/<rid>", "file"),
        ("Report detail", "/api/reports/<int:rid>", "report"),
        ("Note detail", "/api/notes/<int:rid>", "note"),
        ("Task detail", "/api/tasks/<int:rid>", "task"),
        ("Message detail", "/api/messages/<int:rid>", "message"),
        ("Order detail v2", "/api/v2/orders/<int:rid>", "order"),
        ("Customer detail", "/api/customers/<int:rid>", "customer"),
        ("Team member", "/api/team/<int:rid>", "member"),
        ("Invoice v1", "/api/v1/invoices/<rid>", "invoice"),
        ("Document detail", "/api/documents/<int:rid>", "document"),
        ("Attachment detail", "/api/attachments/<int:rid>", "attachment"),
        ("Subscription detail", "/api/subscriptions/<int:rid>", "subscription"),
        ("Payment detail", "/api/payments/<rid>", "payment"),
        ("Refund detail", "/api/refunds/<int:rid>", "refund"),
        ("Card detail", "/api/cards/<int:rid>", "card"),
        ("Audit entry", "/api/audit/<int:rid>", "audit"),
    ]
    for i, (title, route, kind) in enumerate(idor, 1):
        out.append(_mk("idor", i, title, route, "GET", "id",
                       {"kind": kind, "rid": 5000 + 10 * i}))  # spaced: own id (rid-1) never equals another target

    # ------------------------------------------------- Authentication & session (16)
    auth = [
        ("Admin login", "/auth/admin/login", "weak_creds"),
        ("Superuser login", "/auth/superuser/login", "weak_creds"),
        ("Demo login", "/auth/demo/login", "weak_creds"),
        ("Support login", "/auth/support/login", "weak_creds"),
        ("Password reset request", "/account/reset", "reset_predictable"),
        ("Password reset confirm", "/account/reset/confirm", "reset_confirm"),
        ("Admin impersonation", "/admin/impersonate", "cookie_role"),
        ("Remember-me cookie", "/account/remember", "remember_cookie"),
        ("JWT verification", "/api/token/verify", "jwt_none"),
        ("JWT verification v2", "/api/token/verify2", "jwt_weak"),
        ("JWT verification v3", "/api/token/verify3", "jwt_kid"),
        ("Current user API", "/api/v1/me", "jwt_noverify"),
        ("One-time password", "/auth/otp", "otp_fixed"),
        ("Two-factor step", "/auth/2fa", "twofa_bypass"),
        ("OAuth callback", "/auth/oauth/callback", "oauth_state"),
        ("Session fixation", "/auth/session/fixate", "session_fixate"),
    ]
    for i, (title, route, kind) in enumerate(auth, 1):
        out.append(_mk("auth", i, title, route, "GET", "",
                       {"kind": kind,
                        "username": "admin", "password": "admin"} if kind == "weak_creds" else {"kind": kind}))

    # ---------------------------------------------------------- Open redirect (12)
    redir = [
        ("Post-login redirect", "/login/redirect", "next", "none"),
        ("Auth continue", "/auth/continue", "return_to", "none"),
        ("Logout redirect", "/logout", "redirect", "none"),
        ("SSO callback", "/sso/callback", "redirect_uri", "allow_trusted"),
        ("Billing return", "/billing/return", "return_url", "none"),
        ("Support redirect", "/support/redirect", "url", "none"),
        ("Docs redirect", "/docs/redirect", "to", "none"),
        ("App launcher", "/app/launch", "target", "allow_trusted"),
        ("OAuth authorize", "/oauth/authorize", "redirect_uri", "allow_trusted"),
        ("Invite acceptance", "/invite/accept", "next", "none"),
        ("Password reset done", "/password/reset/done", "continue", "none"),
        ("Admin redirect", "/admin/redirect", "url", "none"),
    ]
    for i, (title, route, param, filt) in enumerate(redir, 1):
        out.append(_mk("redirect", i, title, route, "GET", param,
                       {"filter": filt}))

    # ------------------------------------------------------------------ SSTI (12)
    ssti = [
        ("Email preview", "/email/preview", "body", "none"),
        ("Report title", "/reports/title", "title", "none"),
        ("Invoice template", "/invoices/template", "template", "block_double_brace"),
        ("Notification renderer", "/notifications/render", "message", "none"),
        ("PDF header", "/pdf/header", "header", "block_double_brace"),
        ("Signature preview", "/signature/preview", "signature", "none"),
        ("Welcome message", "/welcome/preview", "name", "none"),
        ("Badge printer", "/badges/print", "label", "block_double_brace"),
        ("Reply template", "/tickets/reply-template", "template", "none"),
        ("Export filename", "/exports/filename-template", "filename", "none"),
        ("Dashboard greeting", "/dashboard/greeting", "name", "none"),
        ("Error renderer", "/errors/render", "message", "block_double_brace"),
    ]
    for i, (title, route, param, filt) in enumerate(ssti, 1):
        out.append(_mk("ssti", i, title, route, "GET", param,
                       {"filter": filt}))

    # ----------------------------------------------------------------- Upload (10)
    upload = [
        ("Attachment upload", "/files/upload", "stored_html"),
        ("SVG avatar upload", "/files/upload-svg", "svg"),
        ("Media upload", "/media/upload", "content_type"),
        ("Document upload", "/documents/upload", "double_ext"),
        ("Attachment filename", "/attachments/upload", "traversal_filename"),
        ("Zip import", "/imports/zip", "zip_slip"),
        ("Backup upload", "/backups/upload", "no_size_limit"),
        ("Avatar overwrite", "/avatars/upload", "overwrite"),
        ("JSON upload", "/files/upload-json", "stored_html"),
        ("Template upload", "/templates/upload", "filename_xss"),
    ]
    for i, (title, route, kind) in enumerate(upload, 1):
        out.append(_mk("upload", i, title, route, "POST", "file",
                       {"kind": kind}, difficulty="medium"))

    # ---------------------------------------------------------------- Logic (16)
    logic = [
        ("Add to cart", "/cart/add", "negative_qty"),
        ("Checkout price", "/checkout/price", "price_tamper"),
        ("Coupon application", "/checkout/coupon", "coupon_stack"),
        ("Refund request", "/billing/refund", "refund_abuse"),
        ("Wallet transfer", "/wallet/transfer", "race"),
        ("Currency rounding", "/billing/rounding", "currency_round"),
        ("Shipping calculator", "/checkout/shipping", "shipping_bypass"),
        ("Referral claim", "/referrals/claim", "self_referral"),
        ("Account update", "/account/update", "hidden_admin"),
        ("Workflow approval", "/workflow/approve", "workflow_skip"),
        ("Wallet withdrawal", "/wallet/withdraw", "negative_transfer"),
        ("Gift card redeem", "/gift/redeem", "gift_reuse"),
        ("Trial extension", "/trial/extend", "trial_extend"),
        ("Data export", "/exports/all", "export_all"),
        ("Expense approval", "/expenses/approve", "approve_self"),
        ("Payment limit", "/payments/limit", "limit_bypass"),
    ]
    for i, (title, route, kind) in enumerate(logic, 1):
        out.append(_mk("logic", i, title, route, "POST", "value",
                       {"kind": kind}, difficulty="medium"))

    # ------------------------------------------------------ Info / config (20)
    info = [
        ("Exposed git config", "/.git/config", "info_git"),
        ("Exposed environment file", "/.env", "info_env"),
        ("Downloadable SQL backup", "/backup.sql", "info_backup"),
        ("Server status page", "/server-status", "info_status"),
        ("Debug stack trace", "/debug/stack", "info_debug"),
        ("Actuator environment", "/actuator/env", "info_actuator"),
        ("Metrics endpoint", "/metrics", "info_metrics"),
        ("Application log", "/logs/app.log", "info_log"),
        ("Account profile CORS", "/api/account/profile", "cors"),
        ("Billing CORS", "/api/billing", "cors"),
        ("Admin users CORS", "/api/admin/users", "cors"),
        ("Export CORS", "/api/v1/export", "cors"),
        ("Account settings headers", "/account/settings", "headers"),
        ("Report viewer headers", "/reports/view", "headers"),
        ("Admin panel headers", "/admin/panel", "headers"),
        ("Account security headers", "/account/security", "headers"),
        ("Email change CSRF", "/account/email", "csrf"),
        ("Role change CSRF", "/admin/role", "csrf"),
        ("Locale setter CRLF", "/i18n/set", "crlf"),
        ("Redirect log CRLF", "/redirect/log", "crlf"),
    ]
    for i, (title, route, kind) in enumerate(info, 1):
        if kind == "cors":
            param = "Origin"
        elif kind in ("csrf", "crlf"):
            param = "value"
        else:
            param = ""
        out.append(_mk("info", i, title, route, "GET", param,
                       {"kind": kind}, difficulty="medium"))

    # ----------------------------------------------------------------- NoSQL (6)
    nosql = [
        ("JSON login", "/api/login", "ne"),
        ("User finder", "/api/users/find", "regex"),
        ("Order finder", "/api/orders/find", "or"),
        ("Search API", "/api/search", "where"),
        ("Session lookup", "/api/session", "gt"),
        ("Login API v2", "/api/v2/login", "in"),
    ]
    for i, (title, route, kind) in enumerate(nosql, 1):
        out.append(_mk("nosql", i, title, route, "POST", "json",
                       {"kind": kind}, difficulty="medium"))

    # ------------------------------------------------------------------ LDAP (4)
    ldap = [
        ("Directory search", "/directory/search", "filter"),
        ("LDAP authentication", "/auth/ldap", "login"),
        ("Staff directory", "/staff/search", "filter"),
        ("Directory API", "/api/directory", "filter"),
    ]
    for i, (title, route, kind) in enumerate(ldap, 1):
        out.append(_mk("ldap", i, title, route, "POST" if kind == "login" else "GET",
                       "username" if kind == "login" else "filter",
                       {"kind": kind}, difficulty="medium"))

    # ------------------------------------------------------------------- XXE (6)
    xxe = [
        ("XML invoice import", "/api/xml/import", "body"),
        ("Integration XML", "/integrations/xml", "body"),
        ("Support XML", "/support/xml", "body"),
        ("Order XML", "/orders/xml", "body"),
        ("Report XML", "/reports/xml", "body"),
        ("SOAP endpoint", "/soap/endpoint", "body"),
    ]
    for i, (title, route, param) in enumerate(xxe, 1):
        out.append(_mk("xxe", i, title, route, "POST", param,
                       {"kind": "file"}, difficulty="medium"))

    # --------------------------------------------------------- Host header (4)
    host_header = [
        ("Password reset link", "/account/forgot-password", "email"),
        ("Magic link", "/auth/magic-link", "email"),
        ("Invitation email", "/invite/send", "email"),
        ("Reset API", "/api/password-reset", "email"),
    ]
    for i, (title, route, param) in enumerate(host_header, 1):
        out.append(_mk("host-header", i, title, route, "GET", param,
                       {"kind": "reset"}, difficulty="medium"))

    # ------------------------------------------------ Parameter pollution (4)
    hpp = [
        ("Coupon stacking", "/checkout/apply-coupon", "coupon", "ADMIN100"),
        ("Search filter", "/api/search-hpp", "q", "admin"),
        ("Admin filter", "/admin/filter-hpp", "status", "approved"),
        ("Report scope", "/reports/hpp", "scope", "all"),
    ]
    for i, (title, route, param, privileged) in enumerate(hpp, 1):
        out.append(_mk("hpp", i, title, route, "GET", param,
                       {"privileged": privileged}, difficulty="medium"))

    # ------------------------------------------------------ Cache poisoning (4)
    cache = [
        ("Profile cache", "/cache/profile", "X-Forwarded-Host"),
        ("Home cache", "/cache/home", "X-Forwarded-Host"),
        ("API cache", "/cache/api", "X-Forwarded-Host"),
        ("Asset cache", "/cache/assets", "X-Forwarded-Host"),
    ]
    for i, (title, route, header) in enumerate(cache, 1):
        out.append(_mk("cache", i, title, route, "GET", header,
                       {"header": header}, difficulty="medium"))

    # ------------------------------------------------------- CSV injection (4)
    csv_rows = [
        ("Users CSV export", "/exports/csv/users", "name"),
        ("Tickets CSV export", "/exports/csv/tickets", "subject"),
        ("Audit CSV export", "/exports/csv/audit", "note"),
        ("Invoices CSV export", "/exports/csv/invoices", "memo"),
    ]
    for i, (title, route, param) in enumerate(csv_rows, 1):
        out.append(_mk("csv-injection", i, title, route, "GET", param,
                       {"kind": "csv"}, difficulty="medium"))

    # --------------------------------------------------- Email injection (4)
    email = [
        ("Contact form", "/contact", "email"),
        ("Support email", "/support/email", "email"),
        ("Invitation sender", "/invite/email", "email"),
        ("Email API", "/api/email/send", "email"),
    ]
    for i, (title, route, param) in enumerate(email, 1):
        out.append(_mk("email-injection", i, title, route, "POST", param,
                       {"kind": "header"}, difficulty="medium"))

    # Ensure IDs are assigned in creation order and unique.
    return out


CATALOG: list[Vuln] = _build()
BY_ID: dict[str, Vuln] = {v.id: v for v in CATALOG}


def counts() -> dict[str, int]:
    result: dict[str, int] = {}
    for vuln in CATALOG:
        result[vuln.family] = result.get(vuln.family, 0) + 1
    return result


def manifest() -> list[dict[str, Any]]:
    return [
        {
            "id": v.id,
            "title": v.title,
            "family": v.family,
            "category": v.category,
            "cwe": v.cwe,
            "owasp": v.owasp,
            "difficulty": v.difficulty,
            "method": v.method,
            "route": v.route,
            "param": v.param,
            "objective": v.objective,
        }
        for v in CATALOG
    ]
