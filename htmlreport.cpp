/*
 * SandboxieIOC - self-contained HTML dashboard renderer (implementation).
 */

#include "htmlreport.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonValue>

QString renderNetworkReportHtml(const QJsonObject& report)
{
    const QByteArray json = QJsonDocument(report).toJson(QJsonDocument::Compact);
    QString safeJson = QString::fromUtf8(json);
    safeJson.replace("<", "\\u003c");
    safeJson.replace(">", "\\u003e");

    const QString html = QStringLiteral(R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SandboxieIOC - Network/web report</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Segoe UI", system-ui, -apple-system, Roboto, Helvetica, Arial, sans-serif;
  background: #0e1116;
  color: #e6edf3;
  line-height: 1.5;
}
header {
  padding: 20px 28px;
  background: #161b22;
  border-bottom: 1px solid #30363d;
}
header h1 { margin: 0; font-size: 20px; font-weight: 600; }
header .sub { color: #8b949e; font-size: 13px; margin-top: 4px; word-break: break-all; }
main { padding: 24px 28px; display: grid; gap: 20px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; }
.card {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 8px;
  padding: 14px 16px;
}
.card .num { font-size: 28px; font-weight: 700; }
.card .label { color: #8b949e; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.card.url .num { color: #58a6ff; }
.card.ip .num { color: #3fb950; }
.card.dns .num { color: #d29922; }
.card.conn .num { color: #bc8cff; }
.card.auth .num { color: #f85149; }
section {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 8px;
  padding: 16px 18px;
}
section h2 { margin: 0 0 12px; font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
section h2 .badge {
  background: #30363d; color: #e6edf3; border-radius: 12px;
  padding: 1px 9px; font-size: 12px; font-weight: 500;
}
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid #21262d; vertical-align: top; }
th { color: #8b949e; font-weight: 600; }
td.mono, code { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12.5px; }
.emptystate { color: #6e7681; font-style: italic; padding: 6px 0; }
.tag { border-radius: 4px; padding: 1px 7px; font-size: 11px; background: #21262d; }
.tag.auth { background: #3d1d1d; color: #f85149; }
.pid { color: #8b949e; font-family: ui-monospace, Consolas, monospace; }
pre { white-space: pre-wrap; word-break: break-all; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>SandboxieIOC &mdash; Network / web report</h1>
  <div class="sub" id="subtitle"></div>
</header>
<main>
  <div class="cards">
    <div class="card url"><div class="num" id="c-url">0</div><div class="label">URLs</div></div>
    <div class="card ip"><div class="num" id="c-ip">0</div><div class="label">IP addresses</div></div>
    <div class="card dns"><div class="num" id="c-dns">0</div><div class="label">DNS queries</div></div>
    <div class="card conn"><div class="num" id="c-conn">0</div><div class="label">Connections</div></div>
    <div class="card auth"><div class="num" id="c-auth">0</div><div class="label">Authentication</div></div>
  </div>

  <section id="sec-urls">
    <h2>URLs <span class="badge" id="b-url">0</span></h2>
    <table><thead><tr><th>URL</th></tr></thead><tbody id="t-urls"></tbody></table>
  </section>

  <section id="sec-ips">
    <h2>IP addresses <span class="badge" id="b-ip">0</span></h2>
    <table><thead><tr><th>IP</th></tr></thead><tbody id="t-ips"></tbody></table>
  </section>

  <section id="sec-dns">
    <h2>DNS queries <span class="badge" id="b-dns">0</span></h2>
    <table><thead><tr><th>Domain</th><th>PID</th></tr></thead><tbody id="t-dns"></tbody></table>
  </section>

  <section id="sec-conn">
    <h2>Connections <span class="badge" id="b-conn">0</span></h2>
    <table><thead><tr><th>Endpoint</th><th>IP</th><th>Port</th><th>Proto</th><th>PID</th></tr></thead>
    <tbody id="t-conn"></tbody></table>
  </section>

  <section id="sec-auth">
    <h2>Authentication <span class="badge" id="b-auth">0</span></h2>
    <table><thead><tr><th>Kind</th><th>Evidence</th></tr></thead><tbody id="t-auth"></tbody></table>
  </section>

  <section id="sec-proc">
    <h2>Processes <span class="badge" id="b-proc">0</span></h2>
    <table><thead><tr><th>PID</th><th>Parent</th><th>Name</th><th>Command line</th></tr></thead>
    <tbody id="t-proc"></tbody></table>
  </section>
</main>
)HTML") + QStringLiteral(R"HTML(
<script>
const DATA = __REPORT_JSON__;
const esc = (s) => String(s == null ? "" : s)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
function fillList(id, arr, key) {
  const t = document.getElementById(id);
  if (!arr || !arr.length) { t.innerHTML = '<tr><td class="emptystate">(none)</td></tr>'; return; }
  t.innerHTML = arr.map(i => '<tr><td class="mono">' + esc(i[key]) + '</td></tr>').join("");
}
function render() {
  const iocs = DATA.iocs || {};
  const urls = iocs.urls || [], ips = iocs.ips || [], dns = iocs.domains || [];
  const conns = iocs.connections || [], auth = iocs.authentication || [];
  const procs = DATA.processes || [];
  document.getElementById("c-url").textContent = urls.length;
  document.getElementById("c-ip").textContent = ips.length;
  document.getElementById("c-dns").textContent = dns.length;
  document.getElementById("c-conn").textContent = conns.length;
  document.getElementById("c-auth").textContent = auth.length;
  document.getElementById("b-url").textContent = urls.length;
  document.getElementById("b-ip").textContent = ips.length;
  document.getElementById("b-dns").textContent = dns.length;
  document.getElementById("b-conn").textContent = conns.length;
  document.getElementById("b-auth").textContent = auth.length;
  document.getElementById("b-proc").textContent = procs.length;
  fillList("t-urls", urls, "url");
  fillList("t-ips", ips, "ip");
  {
    const t = document.getElementById("t-dns");
    if (!dns.length) t.innerHTML = '<tr><td class="emptystate">(none)</td></tr>';
    else t.innerHTML = dns.map(d => '<tr><td>' + esc(d.name) + '</td><td class="pid">' + (d.pid != null ? d.pid : '') + '</td></tr>').join("");
  }
  {
    const t = document.getElementById("t-conn");
    if (!conns.length) t.innerHTML = '<tr><td class="emptystate">(none)</td></tr>';
    else t.innerHTML = conns.map(c => '<tr><td class="mono">' + esc(c.endpoint) + '</td><td class="mono">' + esc(c.ip) + '</td><td class="mono">' + esc(c.port) + '</td><td class="mono">' + esc(c.protocol) + '</td><td class="pid">' + (c.pid != null ? c.pid : '') + '</td></tr>').join("");
  }
  {
    const t = document.getElementById("t-auth");
    if (!auth.length) t.innerHTML = '<tr><td class="emptystate">(none)</td></tr>';
    else t.innerHTML = auth.map(a => '<tr><td><span class="tag auth">' + esc(a.kind) + '</span></td><td class="mono">' + esc(a.evidence) + '</td></tr>').join("");
  }
  {
    const t = document.getElementById("t-proc");
    if (!procs.length) t.innerHTML = '<tr><td class="emptystate">(none)</td></tr>';
    else t.innerHTML = procs.map(p => '<tr><td class="pid">' + (p.pid != null ? p.pid : '') + '</td><td class="pid">' + (p.ppid != null ? p.ppid : '') + '</td><td>' + esc(p.name) + '</td><td class="mono">' + esc(p.cmdline) + '</td></tr>').join("");
  }
  const m = DATA.metadata || {};
  document.getElementById("subtitle").textContent =
    "sample: " + (m.sample || "") + "  |  box: " + (m.box || "") +
    "  |  Sandboxie " + (m.sandboxie_version || "") + "  |  " + (m.date || "");
}
render();
</script>
</body>
</html>
)HTML");

    QString out = html;
    out.replace(QStringLiteral("__REPORT_JSON__"), safeJson);
    return out;
}

