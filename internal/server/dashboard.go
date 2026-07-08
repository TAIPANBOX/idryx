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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>idryx — Identity Security Graph</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-gradient: linear-gradient(135deg, #0f172a 0%, #020617 100%);
    --panel-bg: rgba(30, 41, 59, 0.4);
    --panel-border: rgba(255, 255, 255, 0.08);
    --accent: #8b5cf6;
    --accent-hover: #a78bfa;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #3b82f6;
    --info: #14b8a6;
    --human: #3b82f6;
    --service: #a855f7;
    --key: #06b6d4;
    --agent: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: #020617;
    background-image: var(--bg-gradient);
    color: var(--text);
    min-height: 100vh;
    padding: 2rem;
    line-height: 1.5;
  }
  .container {
    max-width: 1400px;
    margin: 0 auto;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--panel-border);
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .logo-icon {
    width: 2rem;
    height: 2rem;
    background: linear-gradient(135deg, var(--accent) 0%, #3b82f6 100%);
    border-radius: 0.5rem;
    box-shadow: 0 0 15px rgba(139, 92, 246, 0.4);
  }
  .logo h1 {
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: -0.025em;
    background: linear-gradient(to right, #ffffff, #a78bfa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .tagline {
    font-size: 0.875rem;
    color: var(--text-muted);
  }
  
  /* Metrics Grid */
  .metrics {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
  }
  .metric-card {
    background: var(--panel-bg);
    border: 1px solid var(--panel-border);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border-radius: 1rem;
    padding: 1.5rem;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .metric-card:hover {
    transform: translateY(-2px);
    border-color: rgba(139, 92, 246, 0.3);
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
  }
  .metric-label {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
  }
  .metric-value {
    font-size: 2.25rem;
    font-weight: 700;
    color: #ffffff;
    line-height: 1.2;
  }
  
  /* Filters and Controls */
  .controls {
    background: var(--panel-bg);
    border: 1px solid var(--panel-border);
    border-radius: 1rem;
    padding: 1.25rem;
    margin-bottom: 2rem;
    display: flex;
    flex-wrap: wrap;
    gap: 1.25rem;
    align-items: center;
    backdrop-filter: blur(12px);
  }
  .search-box {
    flex: 1;
    min-width: 250px;
    position: relative;
  }
  .search-box input {
    width: 100%;
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid var(--panel-border);
    border-radius: 0.75rem;
    padding: 0.75rem 1rem 0.75rem 2.5rem;
    color: var(--text);
    font-family: inherit;
    font-size: 0.9rem;
    transition: all 0.2s;
  }
  .search-box input:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.2);
  }
  .search-box::before {
    content: "🔍";
    position: absolute;
    left: 0.875rem;
    top: 50%;
    transform: translateY(-50%);
    font-size: 0.9rem;
    opacity: 0.5;
  }
  .filter-group {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .filter-label {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--text-muted);
  }
  .filter-pills {
    display: flex;
    gap: 0.375rem;
  }
  .pill {
    background: rgba(15, 23, 42, 0.4);
    border: 1px solid var(--panel-border);
    color: var(--text-muted);
    padding: 0.5rem 0.875rem;
    border-radius: 9999px;
    font-size: 0.825rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
  }
  .pill:hover {
    color: #ffffff;
    border-color: rgba(255, 255, 255, 0.2);
  }
  .pill.active {
    background: var(--accent);
    color: #ffffff;
    border-color: var(--accent);
    box-shadow: 0 4px 12px rgba(139, 92, 246, 0.2);
  }
  
  /* Main Split Panels */
  .panels-grid {
    display: grid;
    grid-template-columns: 420px 1fr;
    gap: 2rem;
    align-items: start;
  }
  
  /* Left Panel: Identities List */
  .panel-left {
    background: var(--panel-bg);
    border: 1px solid var(--panel-border);
    border-radius: 1.25rem;
    backdrop-filter: blur(12px);
    overflow: hidden;
  }
  .panel-title {
    padding: 1.25rem;
    font-size: 1.1rem;
    font-weight: 600;
    border-bottom: 1px solid var(--panel-border);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .panel-subtitle {
    font-size: 0.75rem;
    color: var(--text-muted);
    font-weight: 400;
    background: rgba(255, 255, 255, 0.05);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
  }
  .list-container {
    max-height: 600px;
    overflow-y: auto;
  }
  .identity-row {
    padding: 1.25rem;
    border-bottom: 1px solid var(--panel-border);
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .identity-row:last-child {
    border-bottom: none;
  }
  .identity-row:hover {
    background: rgba(255, 255, 255, 0.03);
  }
  .identity-row.active {
    background: rgba(139, 92, 246, 0.08);
    border-left: 3px solid var(--accent);
  }
  .identity-row-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 0.5rem;
  }
  .identity-id {
    font-weight: 600;
    font-size: 0.95rem;
    color: #ffffff;
    word-break: break-all;
  }
  .identity-row-meta {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.8rem;
    color: var(--text-muted);
  }
  .badge {
    padding: 0.15rem 0.45rem;
    border-radius: 4px;
    font-size: 0.725rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.025em;
  }
  .badge-human { background: rgba(59, 130, 246, 0.12); color: var(--human); border: 1px solid rgba(59, 130, 246, 0.2); }
  .badge-service_account { background: rgba(168, 85, 247, 0.12); color: var(--service); border: 1px solid rgba(168, 85, 247, 0.2); }
  .badge-key { background: rgba(6, 182, 212, 0.12); color: var(--key); border: 1px solid rgba(6, 182, 212, 0.2); }
  .badge-agent { background: rgba(16, 185, 129, 0.12); color: var(--agent); border: 1px solid rgba(16, 185, 129, 0.2); }
  .badge-priv { background: rgba(239, 68, 68, 0.1); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.2); font-size: 0.65rem; }
  
  .alert-count-pill {
    background: var(--critical);
    color: #ffffff;
    font-size: 0.725rem;
    font-weight: 700;
    padding: 0.1rem 0.4rem;
    border-radius: 9999px;
    box-shadow: 0 2px 8px rgba(239, 68, 68, 0.3);
  }

  /* Right Panel: Identity Detail & Graph */
  .panel-right {
    background: var(--panel-bg);
    border: 1px solid var(--panel-border);
    border-radius: 1.25rem;
    backdrop-filter: blur(12px);
    padding: 1.5rem;
    min-height: 500px;
    display: flex;
    flex-direction: column;
  }
  .placeholder-text {
    margin: auto;
    text-align: center;
    color: var(--text-muted);
    font-size: 0.95rem;
    max-width: 320px;
    display: flex;
    flex-direction: column;
    gap: 1rem;
    align-items: center;
  }
  .placeholder-icon {
    font-size: 2.5rem;
    opacity: 0.4;
  }
  
  /* Detail Content styles */
  .detail-content {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }
  .detail-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 1px solid var(--panel-border);
    padding-bottom: 1.25rem;
  }
  .detail-title-group h2 {
    font-size: 1.25rem;
    font-weight: 700;
    word-break: break-all;
    margin-bottom: 0.375rem;
  }
  .detail-title-badges {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }
  
  /* Meta Grid */
  .detail-meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1.25rem;
    background: rgba(15, 23, 42, 0.3);
    border: 1px solid var(--panel-border);
    border-radius: 0.75rem;
    padding: 1.25rem;
  }
  .meta-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .meta-label {
    font-size: 0.75rem;
    font-weight: 500;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .meta-value {
    font-size: 0.875rem;
    font-weight: 600;
    color: #ffffff;
    word-break: break-all;
  }
  
  /* Transitive Delegation Graph Visualizer */
  .delegation-section {
    background: rgba(15, 23, 42, 0.4);
    border: 1px solid var(--panel-border);
    border-radius: 0.75rem;
    padding: 1.25rem;
  }
  .delegation-title {
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-muted);
    margin-bottom: 1rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .delegation-tree {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 0;
  }
  .tree-node {
    background: rgba(15, 23, 42, 0.8);
    border: 1px solid var(--panel-border);
    border-radius: 0.5rem;
    padding: 0.75rem 1.25rem;
    width: 100%;
    max-width: 450px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    box-shadow: 0 4px 15px rgba(0,0,0,0.2);
  }
  .tree-node.active-node {
    border-color: var(--accent);
    box-shadow: 0 4px 15px rgba(139, 92, 246, 0.15);
  }
  .tree-node-info {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .tree-node-id {
    font-weight: 600;
    font-size: 0.875rem;
    word-break: break-all;
  }
  .tree-node-type {
    font-size: 0.7rem;
    color: var(--text-muted);
  }
  .tree-arrow {
    font-size: 1.1rem;
    color: var(--accent);
    animation: bounce 2s infinite;
  }
  @keyframes bounce {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(3px); }
  }
  
  /* Permissions Display */
  .perms-section {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .perms-title {
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .perms-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 0.75rem;
  }
  .perm-card {
    background: rgba(15, 23, 42, 0.3);
    border: 1px solid var(--panel-border);
    border-radius: 0.5rem;
    padding: 0.875rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
  }
  .perm-name {
    font-family: monospace;
    font-size: 0.825rem;
    font-weight: 500;
    word-break: break-all;
  }
  .perm-badges {
    display: flex;
    gap: 0.375rem;
  }
  .pbadge {
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
  }
  .pbadge-admin { background: rgba(239, 68, 68, 0.15); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.2); }
  .pbadge-used { background: rgba(16, 185, 129, 0.15); color: var(--agent); border: 1px solid rgba(16, 185, 129, 0.2); }
  .pbadge-unused { background: rgba(234, 179, 8, 0.15); color: var(--medium); border: 1px solid rgba(234, 179, 8, 0.2); }

  /* Alert List styles */
  .alerts-container {
    background: var(--panel-bg);
    border: 1px solid var(--panel-border);
    border-radius: 1.25rem;
    padding: 1.5rem;
    margin-top: 2rem;
    backdrop-filter: blur(12px);
  }
  .alerts-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.25rem;
  }
  .alerts-header h2 {
    font-size: 1.1rem;
    font-weight: 600;
  }
  .alerts-table-wrapper {
    overflow-x: auto;
  }
  .alerts-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
  }
  .alerts-table th {
    text-align: left;
    padding: 0.75rem 1rem;
    font-weight: 600;
    color: var(--text-muted);
    border-bottom: 1px solid var(--panel-border);
  }
  .alerts-table td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--panel-border);
  }
  .alerts-table tr:last-child td {
    border-bottom: none;
  }
  .sev-col {
    font-weight: 700;
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.05em;
  }
  .sev-critical { color: var(--critical); }
  .sev-high { color: var(--high); }
  .sev-medium { color: var(--medium); }
  .sev-low { color: var(--low); }
  .sev-info { color: var(--info); }
  
  .detector-code {
    font-family: monospace;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.08);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-size: 0.8rem;
  }
  
  /* Scrollbar override */
  ::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }
  ::-webkit-scrollbar-track {
    background: transparent;
  }
  ::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, 0.1);
    border-radius: 3px;
  }
  ::-webkit-scrollbar-thumb:hover {
    background: rgba(255, 255, 255, 0.2);
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">
      <div class="logo-icon"></div>
      <div>
        <h1>idryx</h1>
        <div class="tagline">Identity Security Graph</div>
      </div>
    </div>
    <div class="tagline">Read-Only Monitoring System</div>
  </header>

  <!-- Metric Statistics Cards -->
  <section class="metrics">
    <div class="metric-card">
      <div class="metric-label">Total Identities</div>
      <div class="metric-value" id="stat-total-ids">0</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Active Alerts</div>
      <div class="metric-value" id="stat-active-alerts" style="color: #f87171;">0</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Non-Human Identities</div>
      <div class="metric-value" id="stat-nhi-ids">0</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">AI Agents</div>
      <div class="metric-value" id="stat-agent-ids" style="color: #34d399;">0</div>
    </div>
  </section>

  <!-- Search & Filter Controls -->
  <section class="controls">
    <div class="search-box">
      <input type="text" id="search-input" placeholder="Search identities by ID...">
    </div>
    <div class="filter-group">
      <div class="filter-label">Type:</div>
      <div class="filter-pills" id="type-pills">
        <div class="pill active" data-type="all">All</div>
        <div class="pill" data-type="human">Human</div>
        <div class="pill" data-type="service_account">Service</div>
        <div class="pill" data-type="key">Key</div>
        <div class="pill" data-type="agent">Agent</div>
      </div>
    </div>
    <div class="filter-group">
      <div class="filter-label">Source:</div>
      <div class="filter-pills" id="source-pills">
        <div class="pill active" data-source="all">All</div>
      </div>
    </div>
  </section>

  <!-- Main Split Pane Layout -->
  <div class="panels-grid">
    <!-- Left Pane: Identity Browser -->
    <aside class="panel-left">
      <div class="panel-title">
        <span>Identities</span>
        <span class="panel-subtitle" id="listed-count">0 listed</span>
      </div>
      <div class="list-container" id="identities-list">
        <!-- Rendered dynamically -->
      </div>
    </aside>

    <!-- Right Pane: Details, Permissions and Delegation Chains -->
    <main class="panel-right" id="details-panel">
      <div class="placeholder-text" id="details-placeholder">
        <div class="placeholder-icon">🔏</div>
        <div>Select an identity from the list to analyze its transitive graph, permissions, and timeline context.</div>
      </div>
      <div class="detail-content" id="detail-content" style="display: none;">
        <!-- Filled dynamically -->
      </div>
    </main>
  </div>

  <!-- Bottom Pane: Active Alerts list -->
  <section class="alerts-container">
    <div class="alerts-header">
      <h2>Security Threat & Vulnerability Feed</h2>
    </div>
    <div class="alerts-table-wrapper">
      <table class="alerts-table" id="alerts-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Detector</th>
            <th>Identity</th>
            <th>Time</th>
            <th>Summary</th>
          </tr>
        </thead>
        <tbody id="alerts-body">
          <!-- Rendered dynamically -->
        </tbody>
      </table>
    </div>
  </section>
</div>

<script>
let globalIdentities = [];
let globalAlerts = [];
let selectedIdentityId = null;
let currentFilters = {
  search: '',
  type: 'all',
  source: 'all'
};

function esc(s) {
  if (s === undefined || s === null) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// escJS escapes a value for use inside a JS string literal that itself sits in
// an HTML attribute (e.g. onclick="f('<id>')"). Identity IDs come verbatim from
// ingested inventory/IAM data and may contain quotes, backslashes or angle
// brackets that would otherwise break out of the string and execute. We hex-
// escape every non-alphanumeric character (\xHH); the result is pure
// [A-Za-z0-9] plus \xHH sequences, which is safe in both the JS-string and the
// surrounding HTML-attribute context with no quote/ampersand interaction.
function escJS(s) {
  if (s === undefined || s === null) return '';
  return String(s).replace(/[^a-zA-Z0-9]/g, c => {
    const h = c.charCodeAt(0);
    return h < 256 ? '\\x' + h.toString(16).padStart(2, '0')
                   : '\\u' + h.toString(16).padStart(4, '0');
  });
}

function copyToClipboard(id) {
  const codeEl = document.getElementById('remediation-code-' + id);
  const btn = document.getElementById('copy-btn-' + id);
  if (!codeEl || !btn) return;
  
  navigator.clipboard.writeText(codeEl.textContent).then(() => {
    const originalText = btn.textContent;
    btn.textContent = 'Copied! ✓';
    btn.style.background = 'rgba(16, 185, 129, 0.2)';
    btn.style.color = '#ffffff';
    setTimeout(() => {
      btn.textContent = originalText;
      btn.style.background = 'rgba(16, 185, 129, 0.1)';
      btn.style.color = 'var(--agent)';
    }, 2000);
  });
}

// Fetch all alerts
fetch('api/alerts')
  .then(r => r.json())
  .then(data => {
    globalAlerts = data;
    document.getElementById('stat-active-alerts').textContent = data.length;
    renderAlertsTable();
    initDashboard();
  });

// Fetch all identities
fetch('api/identities')
  .then(r => r.json())
  .then(data => {
    globalIdentities = data;
    document.getElementById('stat-total-ids').textContent = data.length;
    
    // Calculate NHIs (anything that isn't Human) and Agents
    const nhis = data.filter(i => i.type !== 'human');
    const agents = data.filter(i => i.type === 'agent');
    document.getElementById('stat-nhi-ids').textContent = nhis.length;
    document.getElementById('stat-agent-ids').textContent = agents.length;
    
    populateSourcePills(data);
    initDashboard();
  });

function initDashboard() {
  if (globalIdentities.length > 0) {
    applyFiltersAndRender();
  }
}

// Populate Source Pills based on actual ingested identities
function populateSourcePills(data) {
  const sources = new Set();
  data.forEach(i => {
    if (i.source) sources.add(i.source);
  });
  
  const container = document.getElementById('source-pills');
  sources.forEach(src => {
    const pill = document.createElement('div');
    pill.className = 'pill';
    pill.textContent = src;
    pill.dataset.source = src;
    container.appendChild(pill);
  });
  
  // Bind source pill events
  document.querySelectorAll('#source-pills .pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('#source-pills .pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilters.source = pill.dataset.source;
      applyFiltersAndRender();
    });
  });
}

// Bind Type Pill events
document.querySelectorAll('#type-pills .pill').forEach(pill => {
  pill.addEventListener('click', () => {
    document.querySelectorAll('#type-pills .pill').forEach(p => p.classList.remove('active'));
    pill.classList.add('active');
    currentFilters.type = pill.dataset.type;
    applyFiltersAndRender();
  });
});

// Bind search input events
document.getElementById('search-input').addEventListener('input', (e) => {
  currentFilters.search = e.target.value.toLowerCase().trim();
  applyFiltersAndRender();
});

// Filter identities list
function applyFiltersAndRender() {
  let filtered = globalIdentities;
  
  // Search
  if (currentFilters.search) {
    filtered = filtered.filter(i => i.id.toLowerCase().includes(currentFilters.search));
  }
  
  // Type
  if (currentFilters.type !== 'all') {
    filtered = filtered.filter(i => i.type === currentFilters.type);
  }
  
  // Source
  if (currentFilters.source !== 'all') {
    filtered = filtered.filter(i => i.source === currentFilters.source);
  }
  
  document.getElementById('listed-count').textContent = filtered.length + ' listed';
  renderIdentitiesList(filtered);
}

// Render left pane identities
function renderIdentitiesList(list) {
  const container = document.getElementById('identities-list');
  if (list.length === 0) {
    container.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-muted); font-size: 0.875rem;">No matching identities found.</div>';
    return;
  }
  
  container.innerHTML = list.map(i => {
    const isSelected = i.id === selectedIdentityId;
    const typeLabel = i.type === 'human' ? 'Human' : i.type === 'service_account' ? 'Service' : i.type === 'key' ? 'Key' : 'Agent';
    const alertBadge = i.alerts > 0 ? '<span class="alert-count-pill">' + i.alerts + '</span>' : '';
    const privBadge = i.privileged ? '<span class="badge badge-priv">privileged</span>' : '';
    
    return '<div class="identity-row ' + (isSelected ? 'active' : '') + '" onclick="selectIdentity(\'' + esc(i.id) + '\')">' +
           '<div class="identity-row-header">' +
           '<span class="identity-id">' + esc(i.id) + '</span>' +
           alertBadge +
           '</div>' +
           '<div class="identity-row-meta">' +
           '<span class="badge badge-' + esc(i.type) + '">' + esc(typeLabel) + '</span>' +
           privBadge +
           '<span>' + i.events + ' event(s)</span>' +
           '</div>' +
           '</div>';
  }).join('');
}

// Click callback to inspect identity details
function selectIdentity(id) {
  selectedIdentityId = id;
  
  // Highlight in list
  document.querySelectorAll('.identity-row').forEach(row => {
    row.classList.remove('active');
  });
  
  // Re-apply list render to keep active state highlighted correctly
  applyFiltersAndRender();
  
  const identity = globalIdentities.find(i => i.id === id);
  if (!identity) return;
  
  renderDetails(identity);
}

// Render identity details, permissions, and delegation tree
function renderDetails(id) {
  document.getElementById('details-placeholder').style.display = 'none';
  const container = document.getElementById('detail-content');
  container.style.display = 'flex';
  
  const typeLabel = id.type === 'human' ? 'Human' : id.type === 'service_account' ? 'Service Account' : id.type === 'key' ? 'Access Key' : 'AI Agent';
  
  // Build details layout
  let html = '<div class="detail-header">' +
    '<div class="detail-title-group">' +
    '<h2>' + esc(id.id) + '</h2>' +
    '<div class="detail-title-badges">' +
    '<span class="badge badge-' + esc(id.type) + '">' + esc(typeLabel) + '</span>' +
    (id.privileged ? '<span class="badge badge-priv">privileged</span>' : '') +
    (id.source ? '<span style="font-size: 0.8rem; opacity: 0.6;">source: <b>' + esc(id.source) + '</b></span>' : '') +
    '</div>' +
    '</div>' +
    '</div>' +
    '<div class="detail-meta-grid">' +
    '<div class="meta-item">' +
    '<span class="meta-label">Owner</span>' +
    '<span class="meta-value">' + esc(id.owner || 'N/A') + '</span>' +
    '</div>' +
    '<div class="meta-item">' +
    '<span class="meta-label">Created Time</span>' +
    '<span class="meta-value">' + esc(id.created || 'N/A') + '</span>' +
    '</div>' +
    '<div class="meta-item">' +
    '<span class="meta-label">Last Active</span>' +
    '<span class="meta-value">' + esc(id.last_used || 'N/A') + '</span>' +
    '</div>' +
    (id.runtime ? '<div class="meta-item"><span class="meta-label">Runtime Engine</span><span class="meta-value">' + esc(id.runtime) + '</span></div>' : '') +
    '</div>';
  
  // Render Delegation Graph Tree if agent acts on behalf of another entity
  if (id.on_behalf_of) {
    const chain = getDelegationChain(id.id);
    html += '<div class="delegation-section">' +
      '<div class="delegation-title">Delegation & Blast-Radius Graph</div>' +
      '<div class="delegation-tree">';
    
    chain.forEach((linkId, index) => {
      const nodeObj = globalIdentities.find(x => x.id === linkId) || { id: linkId, type: 'unknown' };
      const nodeLabel = nodeObj.type === 'human' ? 'Human User' : nodeObj.type === 'service_account' ? 'Service Account' : nodeObj.type === 'key' ? 'Access Key' : nodeObj.type === 'agent' ? 'AI Agent' : 'External Principal';
      
      html += '<div class="tree-node ' + (index === 0 ? 'active-node' : '') + '">' +
        '<div class="tree-node-info">' +
        '<span class="tree-node-id">' + esc(linkId) + '</span>' +
        '<span class="tree-node-type">' + esc(nodeLabel) + '</span>' +
        '</div>' +
        '<span class="badge badge-' + esc(nodeObj.type) + '">' + esc(nodeObj.type) + '</span>' +
        '</div>';
      
      if (index < chain.length - 1) {
        html += '<div class="tree-arrow">↓</div>';
      }
    });

    html += '</div>';

    // Blast radius: the union of permissions reachable across the whole chain.
    // This is what an attacker gains if this agent is compromised.
    const blast = computeBlastRadius(chain);
    if (blast.length > 0) {
      const adminCount = blast.filter(p => p.admin).length;
      html += '<div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--panel-border);">' +
        '<div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem;">' +
        'Blast radius: <b style="color: #fff;">' + blast.length + '</b> effective permission(s) across the chain' +
        (adminCount > 0 ? ' · <b style="color: var(--critical);">' + adminCount + ' admin-equivalent</b>' : '') +
        '</div>' +
        '<div class="perm-badges" style="flex-wrap: wrap; gap: 0.375rem;">' +
        blast.map(p => '<span class="pbadge ' + (p.admin ? 'pbadge-admin' : 'pbadge-used') + '" title="' + esc(p.source) + '">' + esc(p.name) + '</span>').join('') +
        '</div></div>';
    }

    html += '</div>';
  }
  
  // Render Terraform Remediation if available
  if (id.remediation) {
    html += '<div class="delegation-section" style="border-color: rgba(16, 185, 129, 0.3);">' +
      '<div class="delegation-title" style="color: var(--agent); display: flex; justify-content: space-between; align-items: center;">' +
      '<span>Terraform Right-Sizing Remediation</span>' +
      '<button onclick="copyToClipboard(\'' + escJS(id.id) + '\')" id="copy-btn-' + esc(id.id) + '" style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); color: var(--agent); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; cursor: pointer; transition: all 0.2s;">Copy Terraform</button>' +
      '</div>' +
      '<div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">' + esc(id.remediation.explanation) +
      (id.remediation.created_at ? '<span style="opacity: 0.6;"> · generated ' + esc(id.remediation.created_at) + '</span>' : '') + '</div>' +
      '<pre id="remediation-code-' + esc(id.id) + '" style="background: #090d16; border: 1px solid var(--panel-border); border-radius: 0.5rem; padding: 1rem; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #34d399; text-align: left; max-height: 200px;">' + esc(id.remediation.code) + '</pre>' +
      '</div>';
  }

  // Render Credential Rotation if available
  if (id.rotation) {
    html += '<div class="delegation-section" style="border-color: rgba(234, 179, 8, 0.3);">' +
      '<div class="delegation-title" style="color: var(--medium);">Credential Rotation</div>' +
      '<div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">' + esc(id.rotation.explanation) +
      (id.rotation.created_at ? '<span style="opacity: 0.6;"> · generated ' + esc(id.rotation.created_at) + '</span>' : '') + '</div>' +
      '<pre style="background: #090d16; border: 1px solid var(--panel-border); border-radius: 0.5rem; padding: 1rem; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #fde68a; text-align: left; max-height: 200px;">' + esc(id.rotation.code) + '</pre>' +
      '</div>';
  }

  // Render Permissions list
  if (id.permissions && id.permissions.length > 0) {
    html += '<div class="perms-section">' +
      '<div class="perms-title">Granted Permissions & Capabilities (' + id.permissions.length + ')</div>' +
      '<div class="perms-grid">';
    
    id.permissions.forEach(p => {
      const adminBadge = p.admin ? '<span class="pbadge pbadge-admin">Admin</span>' : '';
      const usageBadge = p.used ? '<span class="pbadge pbadge-used">Used</span>' : '<span class="pbadge pbadge-unused">Unused</span>';
      
      html += '<div class="perm-card">' +
        '<span class="perm-name">' + esc(p.name) + '</span>' +
        '<div class="perm-badges">' +
        adminBadge +
        usageBadge +
        '</div>' +
        '</div>';
    });
    
    html += '</div></div>';
  } else if (id.type !== 'human') {
    html += '<div class="perms-section">' +
      '<div class="perms-title">Granted Permissions & Capabilities</div>' +
      '<div style="padding: 1rem; text-align: center; color: var(--text-muted); font-size: 0.85rem; border: 1px dashed var(--panel-border); border-radius: 0.5rem;">No permissions configured or observed on this non-human identity.</div>' +
      '</div>';
  }
  
  container.innerHTML = html;
}

// Compute the delegation chain path, mirroring graph.WalkDelegationChain on
// the server: on_behalf_of is now a full array (agent-passport SPEC §5,
// ordered root-first, last = immediate principal), so each node can itself
// contribute several hops. We add them immediate-principal-first (i.e. the
// array in reverse), then keep walking from the root of that array in case it
// is itself a node with a further chain of its own to stitch on.
function getDelegationChain(startId) {
  const chain = [];
  const seen = new Set();
  const add = (id) => {
    if (seen.has(id)) return false;
    seen.add(id);
    chain.push(id);
    return true;
  };

  if (!add(startId)) return chain;

  let currentId = startId;
  for (;;) {
    const obj = globalIdentities.find(x => x.id === currentId);
    const obo = obj && obj.on_behalf_of;
    if (!obo || obo.length === 0) break;

    let next = null;
    for (let i = obo.length - 1; i >= 0; i--) {
      if (add(obo[i])) next = obo[i];
    }
    if (next === null) break;
    currentId = next;
  }
  return chain;
}

// Compute the blast radius: the de-duplicated union of permissions across every
// identity in the delegation chain, tagged with the link they come from. This
// mirrors graph.EffectivePermissions on the server.
function computeBlastRadius(chain) {
  const out = [];
  const seen = new Set();
  chain.forEach(linkId => {
    const obj = globalIdentities.find(x => x.id === linkId);
    if (!obj || !obj.permissions) return;
    obj.permissions.forEach(p => {
      if (seen.has(p.name)) return;
      seen.add(p.name);
      out.push({ name: p.name, admin: p.admin, source: linkId });
    });
  });
  // Admin-equivalent permissions first, then by name, for a stable, scannable list.
  out.sort((a, b) => (b.admin - a.admin) || a.name.localeCompare(b.name));
  return out;
}

// Render active threat alerts table
function renderAlertsTable() {
  const tb = document.getElementById('alerts-body');
  if (globalAlerts.length === 0) {
    tb.innerHTML = '<tr><td colspan="5" class="muted" style="text-align: center; padding: 2rem; color: var(--text-muted);">No security alerts generated by active detectors. System baseline matches specifications.</td></tr>';
    return;
  }
  
  tb.innerHTML = globalAlerts.map(a => {
    const timeStr = a.time.replace('T', ' ').replace('Z', ' UTC');
    return '<tr>' +
      '<td class="sev-col sev-' + esc(a.severity) + '">' + esc(a.severity) + '</td>' +
      '<td><span class="detector-code">' + esc(a.detector) + '</span></td>' +
      '<td><a href="#" onclick="selectIdentity(\'' + escJS(a.identity) + '\'); return false;" style="color: var(--accent); text-decoration: none; font-weight: 500;">' + esc(a.identity) + '</a></td>' +
      '<td style="color: var(--text-muted);">' + esc(timeStr) + '</td>' +
      '<td style="font-weight: 500;">' + esc(a.summary) + '</td>' +
      '</tr>';
  }).join('');
}
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
