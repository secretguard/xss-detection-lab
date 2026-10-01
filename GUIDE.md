# Implementation & Demo Guide — Windows / PowerShell (one page)

A step-by-step guide to run, understand, and present this project on **Windows
using PowerShell**. It follows the **Attack → Evidence → Detection → Response**
flow your project is graded on.

> **PowerShell notes (read once):**
> - Run each command on its own line. Windows PowerShell does **not** support
>   `&&` to chain commands — use `;` or separate lines.
> - If `python` is not found, use `py` instead (e.g. `py --version`).
> - Windows `curl` is an alias for `Invoke-WebRequest`. To get real curl
>   behaviour use **`curl.exe`** (ships with Windows 10/11).
> - For Docker, **Docker Desktop must be running** (whale icon in the tray).

## 0. Prerequisites
- **Docker Desktop for Windows** (WSL2 backend) — for the full stack incl. ZAP.
  *Or* just **Python 3.12** (python.org, tick "Add python.exe to PATH") to run
  the app alone.
- **Git for Windows**, and a browser.

Check they are installed (PowerShell):
```powershell
docker --version
py --version
git --version
```

## 1. Get it running (2 minutes)
```powershell
git clone https://github.com/secretguard/xss-detection-lab.git
cd xss-detection-lab
docker compose up --build         # starts the app + headless OWASP ZAP
```
Open **http://localhost:8000/dashboard**. Leave it visible — it updates live.
To stop: press `Ctrl+C`, then `docker compose down`.

**No Docker?** Run the app alone (ZAP button will just say "unavailable"):
```powershell
cd app
py -m pip install -r requirements.txt
py -m uvicorn main:app
```

## 2. Walk the flow (this is your demo)

**① Attack** — open **http://localhost:8000/target/** in a second tab. Click each
one-click attack (body, attribute, script). Each reflects your payload into a
different context.

**② Evidence** — each request is the evidence. The dashboard records every one.
You can also save a response to a file and analyse it with the oracle CLI:
```powershell
curl.exe "http://localhost:8000/target/body?input=ARC_9f3k2" -o evidence.html
py app\oracle.py evidence.html
```

**③ Detection** — watch the dashboard: each attack appears instantly with its
**context** (HTML_BODY / HTML_ATTRIBUTE / SCRIPT …), whether it is
**exploitable**, and a **severity** (SCRIPT = CRITICAL, body/attribute = HIGH).
Then click the **Safe (escaped)** link — it shows **SAFE**. That is your
**negative control**: proof the detector does *not* false-positive on escaped
output.

**④ Response** — flip the **Protect** toggle on and repeat an attack: the payload
is neutralised (auto-escaped + a CSP header is added) and the finding is marked
`mitigated`. Expand any finding to read the **context-specific fix**.

**ZAP (headless):** click **Run ZAP Scan**. ZAP spiders the target, actively
injects XSS payloads, and the XSS alerts it finds flow into the same dashboard.

## 3. Map to your deliverables
| Brief step | Where it is |
|---|---|
| Unique marker + 3 contexts | `app\main.py` (`/target/*`), marker `ARC_9f3k2` |
| Context-identifying oracle (`html.parser`) | `app\oracle.py` |
| Negative control (escaped ≠ vulnerable) | `/target/safe` + `tests\test_oracle.py` |
| Detection + severity | `app\oracle.py`, dashboard cards |
| Response / mitigation | Protect mode in `main.py`, advice in `remediation.py` |
| Evidence files | `samples\` (+ save your own) |

## 4. Prove it works
```powershell
py -m pip install pytest
py -m pytest -q                   # 10 tests: every context + negative control
```
Take screenshots of: the live dashboard after 3 attacks, a SAFE row, a
`mitigated` row in Protect mode, and the ZAP scan results. Those are your Day-4
evidence.

## 5. Code map (where to look / extend)
```
app\main.py         vulnerable target + detection middleware + WebSocket + ZAP control
app\oracle.py       the detector (context + exploitability + severity)   <- core logic
app\remediation.py  context-specific fix advice (the "Response" phase)
app\realtime.py     findings store + WebSocket broadcaster
app\zap_client.py   drives headless OWASP ZAP over its REST API
app\templates\, app\static\   the live dashboard UI
```
**To add a new context** (e.g. `<textarea>`): handle it in `_ContextLocator` in
`oracle.py`, give it a severity in `_SEVERITY`, and add advice in
`remediation.py`. Add a test in `tests\test_oracle.py`.

## 6. Common Windows snags
- **`docker` errors / "cannot connect to the Docker daemon"** → Docker Desktop
  is not running. Start it and wait for the whale icon to go steady.
- **`port is already allocated` / `address already in use`** on 8000 → something
  else uses that port. Edit `docker-compose.yml`, change `"8000:8000"` to
  `"8001:8000"`, re-run, and open `localhost:8001`.
- **`python` not recognised** → use `py` (or reinstall Python with "Add to PATH"
  ticked).
- **`&&` ... "The token '&&' is not a valid statement separator"** → run the
  commands on separate lines (PowerShell), not joined with `&&`.
- **`curl` behaves oddly / errors on `-o`** → use **`curl.exe`**, not `curl`.

## 7. Safety
`/target/*` is **intentionally vulnerable** — run it only locally or on an
isolated lab network, never on a public server.

> Full details: see `README.md`. What changed from the first prototype: `CHANGES.md`.
