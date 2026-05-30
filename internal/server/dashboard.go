package server

import (
	"html/template"
	"net/http"
)

// dashboardTmpl is a single self-contained page: it fetches the JSON APIs and
// renders alerts and identities. No build step, no external assets.
var dashboardTmpl = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>idryx</title>
<style>
  body { font: 14px/1.5 system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
  table { border-collapse: collapse; width: 100%; margin-top: .5rem; }
  th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #eee; }
  th { color: #666; font-weight: 600; }
  .sev { font-weight: 600; text-transform: uppercase; font-size: .75rem; }
  .critical { color: #b00020; } .high { color: #d35400; }
  .medium { color: #b7950b; } .low { color: #2471a3; }
  .priv { color: #b00020; font-size: .75rem; }
  code { background: #f5f5f5; padding: .1rem .3rem; border-radius: 3px; }
  .muted { color: #888; }
</style>
</head>
<body>
<h1>idryx — Identity Security Graph</h1>
<p class="muted">Read-only view. Detection is deterministic; the IdP is never mutated.</p>

<h2>Alerts (<span id="alert-count">…</span>)</h2>
<table id="alerts"><thead><tr>
  <th>Severity</th><th>Detector</th><th>Identity</th><th>Time</th><th>Detail</th>
</tr></thead><tbody></tbody></table>

<h2>Identities (<span id="id-count">…</span>)</h2>
<table id="identities"><thead><tr>
  <th>Identity</th><th>Privileged</th><th>Events</th><th>Alerts</th>
</tr></thead><tbody></tbody></table>

<script>
function esc(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
fetch('api/alerts').then(r=>r.json()).then(rows=>{
  document.getElementById('alert-count').textContent = rows.length;
  const tb = document.querySelector('#alerts tbody');
  if(!rows.length){ tb.innerHTML='<tr><td colspan="5" class="muted">No alerts.</td></tr>'; return; }
  tb.innerHTML = rows.map(a=>
    '<tr><td class="sev '+esc(a.severity)+'">'+esc(a.severity)+'</td>'+
    '<td><code>'+esc(a.detector)+'</code></td><td>'+esc(a.identity)+'</td>'+
    '<td class="muted">'+esc(a.time)+'</td><td>'+esc(a.summary)+'</td></tr>').join('');
});
fetch('api/identities').then(r=>r.json()).then(rows=>{
  document.getElementById('id-count').textContent = rows.length;
  const tb = document.querySelector('#identities tbody');
  if(!rows.length){ tb.innerHTML='<tr><td colspan="4" class="muted">No identities.</td></tr>'; return; }
  tb.innerHTML = rows.map(i=>
    '<tr><td>'+esc(i.id)+'</td>'+
    '<td>'+(i.privileged?'<span class="priv">privileged</span>':'')+'</td>'+
    '<td>'+i.events+'</td><td>'+i.alerts+'</td></tr>').join('');
});
</script>
</body>
</html>`))

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = dashboardTmpl.Execute(w, nil)
}
