# XSS Detection Lab

A small but **complete** web application that detects Cross-Site Scripting
(XSS) reflections **in real time**, grades them by the context they land in,
shows context-specific fixes, can **auto-mitigate** them, and can drive a
**headless OWASP ZAP** scanner to actively find XSS in the target.

Built for the ABES G4 (XSS Detection) project and the
**Attack → Evidence → Detection → Response** flow.

![flow](https://img.shields.io/badge/flow-Attack→Evidence→Detection→Response-blue)

---

## What it does

| Phase | In this app |
|---|---|
| **Attack** | A deliberately vulnerable target (`/target/*`) reflects your input into four contexts: HTML body, HTML attribute, JavaScript, and a *safe* (escaped) control. One-click attack payloads are provided. |
| **Evidence** | Every response is captured by a detection layer; the raw reflection is the evidence. The `oracle.py` CLI can also analyse saved `.html` evidence files. |
| **Detection** | A real `html.parser`-based **oracle** finds the input, names the **context** (body / attribute / event-handler / URL / script / style / comment), decides whether it is actually **exploitable** (did `< > " '` survive?), and grades severity. |
| **Response** | Two parts: (1) **context-specific remediation** shown next to every finding, and (2) a **Protect mode** that neutralises the reflection (HTML-escapes it + sets a CSP header) before the response is served. |

Detections stream to a **live dashboard over WebSocket** — no refresh, updates
as traffic happens.

---

## Architecture

```
                         ┌──────────────────────────────────────┐
  browser / attacker ──▶ │  app  (FastAPI, port 8000)           │
                         │                                      │
                         │  /target/*   vulnerable target       │
                         │     │                                │
                         │     ▼  DetectionLayer (middleware)   │
                         │   oracle.py  → context + severity    │
                         │     │        + remediation           │
                         │     ▼                                │
                         │   realtime.py  ──WebSocket──▶ /dashboard (live UI)
                         │     ▲                                │
                         │     │  imports ZAP XSS alerts        │
                         └─────┼────────────────────────────────┘
                               │ REST API
                         ┌─────▼───────────────┐
                         │  zap  (headless)     │  actively scans /target/
                         │  OWASP ZAP daemon    │  and reports XSS alerts
                         └──────────────────────┘
```

Two detection sources feed one dashboard: the **live oracle** (on real traffic)
and the **ZAP active scanner** (on demand).

---

## Quick start

### Option A — Docker (recommended, includes ZAP)

```bash
docker compose up --build
```

Then open **http://localhost:8000/dashboard**.

- Click **Run ZAP Scan** to actively scan the target headlessly and import the
  XSS alerts ZAP finds.
- Open the target in another tab: **http://localhost:8000/target/** and click
  the one-click attacks — watch the dashboard update live.
- Flip **Protect mode** on and repeat an attack: the payload is neutralised and
  the finding shows `mitigated`.

### Option B — run the app alone (no Docker, no ZAP)

```bash
cd app
pip install -r requirements.txt
uvicorn main:app --reload
```

Everything works except the live ZAP scan button (it reports "ZAP unavailable"
gracefully). Point it at an external ZAP with `ZAP_BASE` if you have one.

### The oracle as a CLI (for saved evidence)

```bash
python app/oracle.py                      # analyse the bundled samples/
python app/oracle.py path/to/response.html
python app/oracle.py --needle 'PAYLOAD' response.html
```

### Tests

```bash
pip install pytest
pytest -q
```

---

## Configuration (env vars)

| Var | Default | Meaning |
|---|---|---|
| `ZAP_BASE` | `http://zap:8080` | ZAP daemon API base URL |
| `ZAP_API_KEY` | *(empty)* | ZAP API key (disabled in the lab compose) |
| `ZAP_TARGET` | `http://app:8000/target/` | what ZAP should scan |

---

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/dashboard` | live dashboard |
| `GET` | `/target/{body,attribute,script,safe}?input=…` | vulnerable target |
| `WS` | `/ws` | realtime findings feed |
| `GET` | `/api/findings` | current findings + stats |
| `POST` | `/api/mode` `{ "mode": "monitor"\|"protect" }` | handling mode |
| `POST` | `/api/clear` | clear findings |
| `GET` | `/api/zap/available` | is the ZAP daemon reachable |
| `POST` | `/api/scan` | start a headless ZAP spider + active scan |

---

## Safety note

The `/target/*` endpoints are **intentionally vulnerable**. Run this only
locally or on an isolated lab network, never on a public server.

## Next steps

- **New here? Follow [GUIDE.md](GUIDE.md)** — a one-page run/demo/implementation walkthrough.
- See **[CHANGES.md](CHANGES.md)** for how this version differs from the original prototype.
