// Live dashboard client: subscribes to the WebSocket feed and renders
// detections as they happen.
(() => {
  const $ = (id) => document.getElementById(id);
  const feed = $("feed");
  const seen = new Map(); // id -> row element

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function setStats(s) {
    if (!s) return;
    $("s_total").textContent = s.total ?? 0;
    $("s_expl").textContent = s.exploitable ?? 0;
    $("s_crit").textContent = s.critical ?? 0;
    $("s_safe").textContent = s.safe ?? 0;
    $("s_zap").textContent = s.from_zap ?? 0;
  }

  function rowHtml(f) {
    const r = f.remediation || {};
    const src = f.source === "zap"
      ? '<span class="tag">ZAP</span>'
      : '<span class="tag">live</span>';
    const sub = f.mitigated ? ' · <span style="color:var(--safe)">mitigated</span>' : "";
    return `
      <div class="sev ${esc(f.severity)}">${esc(f.severity)}</div>
      <div><span class="pay">${esc(f.needle || "(n/a)")}</span></div>
      <div>
        <div class="ctx">${esc(f.context)}</div>
        <div class="meta">${esc(f.context_detail || "")}${sub}</div>
      </div>
      <div class="src">${src}</div>
      <div class="detail">
        <h4>${esc(r.title || "")}</h4>
        <p>${esc(r.detail || "")}</p>
        ${r.fix ? `<p><strong>Fix:</strong> ${esc(r.fix)}</p>` : ""}
        ${r.code ? `<code>${esc(r.code)}</code>` : ""}
        ${f.zap && f.zap.url ? `<p class="meta">ZAP: ${esc(f.zap.url)} · param <b>${esc(f.zap.param)}</b> · attack <code>${esc(f.zap.attack)}</code></p>` : ""}
      </div>`;
  }

  function addFinding(f, prepend = true) {
    if (seen.has(f.id)) return;
    $("empty")?.remove();
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = rowHtml(f);
    row.addEventListener("click", () =>
      row.querySelector(".detail").classList.toggle("show"));
    if (prepend && feed.firstChild) feed.insertBefore(row, feed.firstChild);
    else feed.appendChild(row);
    seen.set(f.id, row);
  }

  // ---- scan progress ----
  function scan(stage, percent, message, done) {
    const bar = $("scanbar"), fill = $("scanfill"), msg = $("scanmsg");
    bar.classList.add("show");
    fill.style.width = (percent || 0) + "%";
    msg.textContent = message || "";
    if (stage === "complete" || stage === "error") {
      $("scanBtn").disabled = false;
      $("scanBtn").textContent = "▶ Run ZAP Scan";
      setTimeout(() => bar.classList.remove("show"), 2500);
    }
  }

  // ---- websocket ----
  let ws;
  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onopen = () => {
      $("dot").classList.add("on");
      $("connText").textContent = "live";
      setInterval(() => { if (ws.readyState === 1) ws.send("ping"); }, 25000);
    };
    ws.onclose = () => {
      $("dot").classList.remove("on");
      $("connText").textContent = "reconnecting…";
      setTimeout(connect, 1500);
    };
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.type === "snapshot") {
        (m.findings || []).forEach((f) => addFinding(f, false));
        setStats(m.stats);
        if (m.mode) setMode(m.mode, false);
      } else if (m.type === "finding") {
        addFinding(m.finding, true);
        setStats(m.stats);
      } else if (m.type === "cleared") {
        feed.innerHTML = "";
        seen.clear();
        setStats(m.stats);
      } else if (m.type === "mode") {
        setMode(m.mode, false);
      } else if (m.type === "scan") {
        scan(m.stage, m.percent, m.message);
      }
    };
  }

  // ---- controls ----
  function setMode(mode, push = true) {
    document.querySelectorAll("#modeToggle button").forEach((b) =>
      b.classList.toggle("active", b.dataset.mode === mode));
    if (push) {
      fetch("/api/mode", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode }),
      });
    }
  }

  document.querySelectorAll("#modeToggle button").forEach((b) =>
    b.addEventListener("click", () => setMode(b.dataset.mode)));

  $("clearBtn").addEventListener("click", () =>
    fetch("/api/clear", { method: "POST" }));

  $("scanBtn").addEventListener("click", () => {
    $("scanBtn").disabled = true;
    $("scanBtn").textContent = "Scanning…";
    fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }).then((r) => r.json()).then((d) => {
      if (!d.ok) {
        $("scanBtn").disabled = false;
        $("scanBtn").textContent = "▶ Run ZAP Scan";
        $("scanmsg").textContent = d.error || "could not start scan";
      }
    });
  });

  connect();
})();
