# What changed — from the original prototype to this version

This document maps the original submission (`app.py` + `oracle.py`, a Flask app
with a static dashboard) to the reworked **XSS Detection Lab**, and explains
*why* each change was made. The project goal and the
Attack → Evidence → Detection → Response flow are unchanged — the detection is
now real, the app is real, and ZAP is actually used.

---

## At a glance

| Area | Original | This version |
|---|---|---|
| App type | Flask, static reflection pages + one dashboard page you refresh by hand | FastAPI app: vulnerable target + **realtime** detection + **live** dashboard |
| Detection engine | `oracle.py` using `str.find()` / substring matching | `oracle.py` rebuilt on the standard-library **`html.parser`** (as the brief recommends) |
| Contexts detected | body / attribute / script | body / attribute / **event-handler** / **URL attribute** / script / **style** / **comment** |
| "Is it dangerous?" | assumed from context only | decided by whether **breakout characters `< > " '` survived unescaped** (real exploitability) |
| Escaped / negative control | special-cased a few `&lt;MARKER&gt;` strings | general: compares **raw** vs **HTML-escaped** reflection of the full payload |
| Realtime | none — refresh the page to see new rows | **WebSocket** push; dashboard updates the instant a request is detected |
| Handling / Response | advice implied by a severity label | **Monitor/Protect toggle** that auto-escapes the reflection + sets a CSP header, plus **context-specific remediation** text per finding |
| OWASP ZAP | mentioned, never used | **headless ZAP daemon** driven over its REST API: spider + active scan → XSS alerts imported into the same dashboard |
| Deploy | run `python app.py` | `docker compose up` (app + ZAP) — matches the G4 web/Docker brief |
| Tests | none | `pytest` suite proving every context + the negative control |

---

## 1. The oracle is now a real parser, not string matching

**Original** (`oracle.py`) located the marker and guessed the context with raw
string operations:

```python
last_open_tag = before_marker.rfind("<")
last_close_tag = before_marker.rfind(">")
if last_open_tag > last_close_tag:
    return {"context": "HTML_ATTRIBUTE", ...}
```

This breaks on realistic markup (nested tags, quotes inside text, `>` inside a
JS string, multiple reflections) and it decides "safe" by hard-coding a handful
of `&lt;MARKER&gt;` spellings.

**Now** the oracle feeds the response to Python's `html.parser.HTMLParser` and
records the context from the parser's own callbacks:

- `handle_starttag` → inspects each **attribute value**, and distinguishes
  `on*` event handlers and URL attributes (`href`, `src`, …) from ordinary ones;
- a `<script>` / `<style>` flag → **script** / **style** context in
  `handle_data`;
- `handle_comment` → **comment** context;
- otherwise → **body** context.

This is exactly the approach the project brief asked for
("*use html.parser: track whether you are inside a `<script>`, check start-tag
attribute values, else treat a data section as body*").

## 2. Detection now proves *exploitability*, not just reflection

The original reported `reflected: true/false`. Reflection alone is not a
vulnerability — escaped reflection is the *fixed* state. The new oracle checks
whether the attacker's **context-breaking characters (`< > " '`) survived raw**:

- raw payload present **and** it contained breakout chars → **exploitable**,
  severity by context (script/event-handler = CRITICAL, body/attribute/URL =
  HIGH, …);
- only the **HTML-escaped** form present → **SAFE** (the negative control);
- reflected with no breakout chars → **LOW** (informational).

This makes the Day-3 "prove a safely-escaped marker is not flagged" step work
for *any* payload, not just the few spellings that were hard-coded.

## 3. From "a dashboard you refresh" to realtime

The original stored findings in a list and rendered a full HTML page; you had to
click **Refresh Dashboard** to see anything new. Now:

- a **detection middleware** (`DetectionLayer`) runs the oracle on every
  `/target/*` response automatically;
- findings are pushed over a **WebSocket** (`realtime.py`);
- the dashboard (`templates/dashboard.html` + `static/dashboard.js`) renders
  each finding the moment it happens, with live stat cards and expandable
  remediation.

## 4. Handling / Response is now an actual action

"Response" used to be just a severity word. Now there is a **Monitor / Protect**
toggle:

- **Monitor** — detect and report only;
- **Protect** — the middleware **neutralises** the reflection (HTML-escapes the
  payload) and adds a `Content-Security-Policy` header *before the response is
  sent*, and the finding is marked `mitigated`.

Plus every finding carries **context-specific remediation** (`remediation.py`):
the correct fix for a script context is different from an attribute context, and
the app now says which.

## 5. OWASP ZAP is actually used (headless)

The brief wanted ZAP; the original never called it. Now `docker-compose.yml`
runs the official **ZAP daemon headless**, and `zap_client.py` drives it over
its REST API: spider the target, run the **active scanner** (ZAP injects its own
XSS payloads), then pull back the **XSS alerts** and import them into the same
live feed. If ZAP is not running, the scan button fails gracefully instead of
crashing.

## 6. A proper, reproducible project

- **FastAPI** (async, native WebSockets) instead of a single Flask file.
- Clear module split: `main.py` (app), `oracle.py` (detection), `remediation.py`
  (response advice), `realtime.py` (store + WebSocket), `zap_client.py` (ZAP).
- **Docker Compose** one-command deploy (web/Docker, as the G4 brief specifies).
- A **`pytest` suite** that proves each context and the escaped negative control.

---

## What was intentionally kept

- The **marker** idea (a unique token to locate the input unambiguously).
- The **three core contexts** (body / attribute / script) plus the **escaped
  negative control** — the heart of the assignment.
- The **`oracle.py` CLI** that analyses saved `.html` evidence files, so the
  Day-2 / Day-3 evidence workflow still works (now parser-backed).
