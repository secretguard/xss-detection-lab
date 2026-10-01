"""
XSS Detection Lab - FastAPI application.

Pieces:
  * /target/*        a deliberately vulnerable target (body / attribute /
                     script / safe reflection contexts) - the thing we attack.
  * DetectionLayer   middleware that runs the oracle on every target response
                     in realtime, publishes findings over WebSocket, and - in
                     Protect mode - neutralises the reflection before it is
                     served (the "Response"/handling phase).
  * /ws              WebSocket feed the dashboard subscribes to.
  * /api/*           mode toggle, findings, clear, and ZAP scan control.
  * /dashboard       the live dashboard UI.

Run standalone:   uvicorn main:app --reload   (ZAP features degrade gracefully)
Run with ZAP:     docker compose up
"""

from __future__ import annotations

import asyncio
import html as html_mod
import time
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

import oracle
import realtime
import zap_client

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

MARKER = oracle.MARKER

# Quick-attack payloads surfaced on the target page so a single click produces
# a real, exploitable finding in each context.
PAYLOADS = {
    "body": f'{MARKER}<svg/onload=alert(1)>',
    "attribute": f'{MARKER}" onmouseover="alert(1)',
    "script": f'{MARKER}";alert(1);//',
}


class AppState:
    mode = "monitor"            # "monitor" | "protect"
    scan_running = False
    last_scan: dict | None = None


state = AppState()


# ----------------------------------------------------------------------
# The vulnerable target. Values are reflected UNESCAPED on purpose (except
# /safe), so the oracle has real reflections to detect.
# ----------------------------------------------------------------------
def _page(title: str, body_html: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title></head>
<body style="font-family:system-ui;max-width:760px;margin:40px auto;color:#1f2937">
<p><a href="/target/">&larr; target home</a> &nbsp;|&nbsp; <a href="/dashboard">open dashboard</a></p>
<h1>{title}</h1>
{body_html}
</body></html>"""


app = FastAPI(title="XSS Detection Lab")


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse("/dashboard")


@app.get("/target/", response_class=HTMLResponse)
async def target_home():
    rows = "".join(
        f'<li><a href="/target/{ctx}?input={html_mod.escape(p, quote=True)}">'
        f'Attack {ctx} context</a> '
        f'<code style="background:#f1f5f9;padding:2px 6px;border-radius:4px">{html_mod.escape(p)}</code></li>'
        for ctx, p in PAYLOADS.items()
    )
    return _page("Vulnerable Target", f"""
    <p>A deliberately vulnerable app. Each link reflects your input into a
    different context. Watch the <a href="/dashboard">dashboard</a> update live.</p>
    <ul>{rows}
      <li><a href="/target/safe?input={MARKER}&lt;script&gt;">Safe (escaped) reflection</a> - negative control</li>
    </ul>
    <form action="/target/body" method="get">
      <input name="input" value="{MARKER}" style="width:60%;padding:6px">
      <button>Reflect in body</button>
    </form>""")


@app.get("/target/body", response_class=HTMLResponse)
async def target_body(request: Request):
    value = request.query_params.get("input") or MARKER
    return _page("HTML Body Context",
                 f"<p>Reflected value: {value}</p>")   # vulnerable: raw reflect


@app.get("/target/attribute", response_class=HTMLResponse)
async def target_attribute(request: Request):
    value = request.query_params.get("input") or MARKER
    return _page("HTML Attribute Context",
                 f'<input type="text" value="{value}">')  # vulnerable: raw reflect


@app.get("/target/script", response_class=HTMLResponse)
async def target_script(request: Request):
    value = request.query_params.get("input") or MARKER
    return _page("JavaScript Context", f"""
    <p>Open the console.</p>
    <script>
      const reflected = "{value}";
      console.log(reflected);
    </script>""")   # vulnerable: raw reflect into JS string


@app.get("/target/safe", response_class=HTMLResponse)
async def target_safe(request: Request):
    value = request.query_params.get("input") or MARKER
    safe = html_mod.escape(value, quote=True)             # the FIX applied
    return _page("Safely Escaped Reflection",
                 f"<p>Safe reflected value: {safe}</p>")


# ----------------------------------------------------------------------
# Detection layer - runs on every /target response.
# ----------------------------------------------------------------------
_ANALYSED_PATHS = {"/target/body", "/target/attribute",
                   "/target/script", "/target/safe"}


def _mitigate(html_text: str, submitted: str) -> str:
    """Protect mode: neutralise the reflection by HTML-escaping it."""
    escaped = html_mod.escape(submitted, quote=True)
    return html_text.replace(submitted, escaped)


class DetectionLayer(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if request.url.path not in _ANALYSED_PATHS:
            return response

        body = b""
        async for chunk in response.body_iterator:
            body += chunk
        html_text = body.decode("utf-8", "replace")

        submitted = request.query_params.get("input") or MARKER
        finding = oracle.analyze(html_text, submitted)

        headers = dict(response.headers)
        headers.pop("content-length", None)
        mitigated = False

        if state.mode == "protect" and finding["exploitable"]:
            html_text = _mitigate(html_text, submitted)
            headers["content-security-policy"] = "default-src 'self'; script-src 'self'"
            headers["x-xss-lab-action"] = "mitigated"
            mitigated = True
            # re-evaluate so the dashboard shows the neutralised state
            finding = oracle.analyze(html_text, submitted)

        if finding["context"] != "NOT_FOUND":
            finding["source"] = "live"
            finding["endpoint"] = request.url.path
            finding["mode"] = state.mode
            finding["mitigated"] = mitigated
            await realtime.publish(finding)

        return Response(content=html_text, status_code=response.status_code,
                        headers=headers, media_type="text/html")


app.add_middleware(DetectionLayer)


# ----------------------------------------------------------------------
# Realtime feed
# ----------------------------------------------------------------------
@app.websocket("/ws")
async def ws(ws: WebSocket):
    await realtime.manager.connect(ws)
    try:
        await ws.send_json({"type": "snapshot",
                            "findings": realtime.store.all(),
                            "stats": realtime.store.stats(),
                            "mode": state.mode})
        while True:
            await ws.receive_text()  # keepalive; client never sends real data
    except WebSocketDisconnect:
        await realtime.manager.disconnect(ws)
    except Exception:
        await realtime.manager.disconnect(ws)


# ----------------------------------------------------------------------
# API
# ----------------------------------------------------------------------
@app.get("/api/findings")
async def api_findings():
    return {"findings": realtime.store.all(), "stats": realtime.store.stats(),
            "mode": state.mode}


@app.post("/api/clear")
async def api_clear():
    realtime.store.clear()
    await realtime.manager.broadcast({"type": "cleared",
                                      "stats": realtime.store.stats()})
    return {"ok": True}


@app.post("/api/mode")
async def api_mode(request: Request):
    data = await request.json()
    mode = data.get("mode")
    if mode in ("monitor", "protect"):
        state.mode = mode
        await realtime.manager.broadcast({"type": "mode", "mode": mode})
        return {"ok": True, "mode": mode}
    return JSONResponse({"ok": False, "error": "invalid mode"}, status_code=400)


@app.get("/api/zap/available")
async def api_zap_available():
    return {"available": await zap_client.is_available(),
            "target": zap_client.ZAP_TARGET}


@app.post("/api/scan")
async def api_scan(request: Request):
    if state.scan_running:
        return JSONResponse({"ok": False, "error": "scan already running"},
                            status_code=409)

    data = {}
    try:
        data = await request.json()
    except Exception:
        pass
    target = data.get("target") or zap_client.ZAP_TARGET

    async def on_progress(stage, percent, message):
        await realtime.manager.broadcast({
            "type": "scan", "stage": stage, "percent": percent,
            "message": message, "ts": time.time()})

    async def run():
        state.scan_running = True
        try:
            result = await zap_client.run_scan(target, on_progress=on_progress)
            state.last_scan = result
            for alert in result.get("alerts", []):
                await realtime.publish(zap_client.alert_to_finding(alert))
            await realtime.manager.broadcast({
                "type": "scan", "stage": "complete", "percent": 100,
                "message": (f"Imported {len(result.get('alerts', []))} "
                            f"XSS alert(s) from ZAP") if result.get("ok")
                           else result.get("error", "scan failed"),
                "ok": result.get("ok", False)})
        finally:
            state.scan_running = False

    asyncio.create_task(run())
    return {"ok": True, "started": True, "target": target}


# ----------------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------------
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {
        "marker": MARKER, "payloads": PAYLOADS})


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
