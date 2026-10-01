"""
Headless OWASP ZAP driver.

The original project mentioned ZAP but never actually used it. Here ZAP runs
as a real headless daemon (see docker-compose.yml) and we drive it over its
REST API to *actively find* XSS in the target: spider the site, run the active
scanner, then pull back the XSS alerts.

Everything degrades gracefully: if the ZAP daemon is not reachable (e.g. the
app is run standalone without Docker) the scan endpoint returns a clear
"ZAP unavailable" message instead of crashing.
"""

from __future__ import annotations

import asyncio
import os

import httpx

ZAP_BASE = os.environ.get("ZAP_BASE", "http://zap:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")  # compose disables the key for the lab
# What ZAP should scan. Defaults to this app's own vulnerable target.
ZAP_TARGET = os.environ.get("ZAP_TARGET", "http://app:8000/target/")

_TIMEOUT = httpx.Timeout(20.0)


def _params(**kw) -> dict:
    kw = {k: v for k, v in kw.items() if v is not None}
    if ZAP_API_KEY:
        kw["apikey"] = ZAP_API_KEY
    return kw


async def _get(client: httpx.AsyncClient, view: str, **params):
    r = await client.get(f"{ZAP_BASE}/JSON/{view}/", params=_params(**params))
    r.raise_for_status()
    return r.json()


async def is_available() -> bool:
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(4.0)) as client:
            await _get(client, "core/view/version")
        return True
    except Exception:
        return False


async def run_scan(target: str | None = None, *, on_progress=None) -> dict:
    """Spider + active-scan ``target`` and return the XSS alerts ZAP found.

    ``on_progress(stage, percent, message)`` is an optional async callback used
    to stream progress to the dashboard.
    """
    target = target or ZAP_TARGET

    async def progress(stage, percent, message):
        if on_progress:
            await on_progress(stage, percent, message)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            await progress("starting", 0, f"Connecting to ZAP for {target}")

            # 1) Spider to discover endpoints/parameters.
            spider = await _get(client, "spider/action/scan", url=target,
                                recurse="true")
            sid = spider.get("scan")
            while True:
                status = await _get(client, "spider/view/status", scanId=sid)
                pct = int(status.get("status", 0))
                await progress("spider", pct, f"Spidering target ({pct}%)")
                if pct >= 100:
                    break
                await asyncio.sleep(1.0)

            # 2) Active scan - this is where ZAP injects XSS payloads.
            ascan = await _get(client, "ascan/action/scan", url=target,
                               recurse="true", inScopeOnly="false")
            aid = ascan.get("scan")
            while True:
                status = await _get(client, "ascan/view/status", scanId=aid)
                pct = int(status.get("status", 0))
                await progress("active-scan", pct, f"Active scanning ({pct}%)")
                if pct >= 100:
                    break
                await asyncio.sleep(2.0)

            # 3) Collect XSS alerts.
            alerts = await _get(client, "core/view/alerts", baseurl=target)
            xss = [a for a in alerts.get("alerts", [])
                   if "xss" in a.get("alert", "").lower()
                   or "cross site scripting" in a.get("alert", "").lower()
                   or "cross-site scripting" in a.get("name", "").lower()]
            await progress("done", 100, f"ZAP finished - {len(xss)} XSS alert(s)")
            return {"ok": True, "target": target, "alerts": xss,
                    "total_alerts": len(alerts.get("alerts", []))}

    except Exception as exc:  # noqa: BLE001 - surface a friendly message
        await progress("error", 0, f"ZAP unavailable: {exc}")
        return {"ok": False, "target": target, "error": str(exc), "alerts": []}


def alert_to_finding(alert: dict) -> dict:
    """Normalise a ZAP alert into our dashboard finding shape."""
    risk = alert.get("risk", "Medium").upper()
    severity = {"HIGH": "HIGH", "MEDIUM": "MEDIUM",
                "LOW": "LOW", "INFORMATIONAL": "LOW"}.get(risk, "MEDIUM")
    if "critical" in risk.lower():
        severity = "CRITICAL"
    return {
        "source": "zap",
        "needle": alert.get("param", "") or alert.get("attack", ""),
        "context": "ZAP_ACTIVE_SCAN",
        "context_detail": alert.get("url", ""),
        "reflected": True,
        "raw_reflected": True,
        "safely_escaped": False,
        "exploitable": severity in ("CRITICAL", "HIGH"),
        "severity": severity,
        "remediation": {
            "title": alert.get("alert", "Cross Site Scripting"),
            "detail": _strip_html(alert.get("description", "")),
            "fix": _strip_html(alert.get("solution", "")),
            "code": alert.get("attack", ""),
        },
        "zap": {
            "url": alert.get("url", ""),
            "param": alert.get("param", ""),
            "attack": alert.get("attack", ""),
            "evidence": alert.get("evidence", ""),
            "confidence": alert.get("confidence", ""),
        },
    }


def _strip_html(text: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", text or "").strip()
