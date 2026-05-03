DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced IDS Dashboard - Enhanced Control Center</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @keyframes slideIn { from { opacity:0; transform:translateY(-10px); } to { opacity:1; transform:translateY(0); } }
        @keyframes fadeSlide { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }

        /* ── Top Attackers ── */
        #top-attackers-list { display:flex; flex-direction:column; gap:14px; }
        .top-attacker-item {
            background:linear-gradient(145deg,rgba(15,23,42,.9),rgba(2,6,23,.9));
            border:1px solid rgba(148,163,184,.15); border-radius:14px; padding:16px 18px;
            box-shadow:0 10px 30px rgba(0,0,0,.45); transition:all .3s; position:relative; overflow:hidden;
            animation:fadeSlide .4s ease forwards;
        }
        .top-attacker-item:hover { transform:translateY(-3px) scale(1.01); box-shadow:0 20px 45px rgba(0,0,0,.6); }
        .top-attacker-item::before { content:""; position:absolute; left:0; top:0; height:100%; width:4px; background:linear-gradient(to bottom,#22d3ee,#6366f1); }
        .attacker-ip { font-size:15px; font-weight:600; color:#e5e7eb; display:flex; align-items:center; justify-content:space-between; }
        .country-badge { background:rgba(99,102,241,.15); color:#a5b4fc; padding:2px 8px; border-radius:999px; font-size:11px; }
        .attacker-stats { display:flex; flex-wrap:wrap; gap:14px; margin-top:10px; font-size:13px; }
        .stat { display:flex; align-items:center; gap:6px; color:#cbd5f5; }
        .stat.critical { color:#f87171; text-shadow:0 0 10px rgba(248,113,113,.4); }
        .stat.high { color:#fbbf24; text-shadow:0 0 10px rgba(251,191,36,.35); }
        .blacklisted { background:rgba(239,68,68,.15); color:#fecaca; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:600; }

        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:'Inter',-apple-system,sans-serif; background:linear-gradient(135deg,#0a0e27 0%,#1a1f3a 100%); color:#e4e7eb; min-height:100vh; }
        .container { max-width:1920px; margin:0 auto; padding:20px; }

        /* Loading overlay */
        .loading-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(10,14,39,.98); display:flex; justify-content:center; align-items:center; z-index:9999; flex-direction:column; gap:30px; }
        .loading-overlay.hidden { display:none; }
        .spinner { width:80px; height:80px; border:8px solid rgba(96,165,250,.1); border-top:8px solid #60a5fa; border-radius:50%; animation:spin 1s linear infinite; }
        @keyframes spin { 0% { transform:rotate(0deg); } 100% { transform:rotate(360deg); } }
        .loading-text { color:#60a5fa; font-size:1.5em; font-weight:600; }

        /* Tabs */
        .tabs { display:flex; gap:10px; margin-bottom:30px; background:rgba(30,41,59,.5); padding:10px; border-radius:15px; }
        .tab { padding:15px 30px; background:transparent; border:2px solid transparent; border-radius:12px; color:#94a3b8; font-weight:600; cursor:pointer; transition:all .3s; display:flex; align-items:center; gap:10px; }
        .tab:hover { background:rgba(96,165,250,.1); border-color:rgba(96,165,250,.3); }
        .tab.active { background:linear-gradient(135deg,#3b82f6,#2563eb); color:white; border-color:#3b82f6; }
        .tab-content { display:none; }
        .tab-content.active { display:block; }

        /* Header */
        .header { background:linear-gradient(135deg,#1e293b 0%,#334155 100%); padding:30px 40px; border-radius:20px; margin-bottom:30px; display:flex; justify-content:space-between; align-items:center; box-shadow:0 10px 30px rgba(0,0,0,.5); }
        .header h1 { font-size:2.2em; background:linear-gradient(135deg,#60a5fa,#a78bfa,#ec4899); -webkit-background-clip:text; -webkit-text-fill-color:transparent; font-weight:800; }
        .header-subtitle { color:#94a3b8; margin-top:10px; font-size:1em; }
        .badge { display:inline-block; padding:6px 14px; border-radius:15px; font-size:.75em; font-weight:700; margin-left:10px; }
        .badge-ml { background:linear-gradient(135deg,#a78bfa,#ec4899); }
        .badge-pro { background:linear-gradient(135deg,#60a5fa,#3b82f6); }

        /* Status */
        .status-pill { display:flex; align-items:center; gap:12px; background:rgba(34,197,94,.15); padding:15px 25px; border-radius:25px; border:2px solid #22c55e; box-shadow:0 0 20px rgba(34,197,94,.3); }
        .status-pill.initializing { background:rgba(251,191,36,.15); border-color:#fbbf24; box-shadow:0 0 20px rgba(251,191,36,.3); }
        .status-dot { width:12px; height:12px; border-radius:50%; background:#22c55e; animation:pulse 2s infinite; }
        .status-dot.initializing { background:#fbbf24; }
        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.5; } }

        .btn-export { background:linear-gradient(135deg,#3b82f6,#2563eb); color:white; border:none; padding:12px 24px; border-radius:12px; font-weight:600; cursor:pointer; transition:all .3s; }
        .btn-export:hover { transform:translateY(-2px); box-shadow:0 10px 25px rgba(59,130,246,.4); }
        .btn-logout { background:linear-gradient(135deg,#64748b,#334155); color:white; border:none; padding:12px 24px; border-radius:12px; font-weight:600; cursor:pointer; transition:all .3s; }
        .btn-logout:hover { transform:translateY(-2px); box-shadow:0 10px 25px rgba(100,116,139,.4); }

        /* Control section */
        .control-section { background:rgba(30,41,59,.8); padding:30px; border-radius:20px; border:1px solid rgba(96,165,250,.2); margin-bottom:30px; }
        .control-header { display:flex; align-items:center; gap:15px; margin-bottom:25px; padding-bottom:15px; border-bottom:2px solid rgba(96,165,250,.2); }
        .control-header i { font-size:2em; color:#60a5fa; }
        .control-header h2 { font-size:1.8em; font-weight:700; }

        /* Model grid */
        .model-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:20px; margin-top:20px; }
        .model-option { background:linear-gradient(135deg,rgba(15,23,42,.9),rgba(30,41,59,.9)); padding:25px; border-radius:15px; border:2px solid rgba(96,165,250,.3); cursor:pointer; transition:all .3s; position:relative; }
        .model-option:hover { transform:translateY(-5px); border-color:rgba(96,165,250,.6); box-shadow:0 10px 30px rgba(96,165,250,.3); }
        .model-option.active { border-color:#22c55e; background:linear-gradient(135deg,rgba(34,197,94,.2),rgba(30,41,59,.9)); }
        .model-option.active::before { content:'✓'; position:absolute; top:10px; right:10px; width:30px; height:30px; background:#22c55e; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:bold; }
        .model-name { font-size:1.3em; font-weight:700; margin-bottom:10px; color:#60a5fa; }
        .model-desc { color:#94a3b8; font-size:.9em; line-height:1.6; }

        /* Stats grid */
        .stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:20px; margin-bottom:30px; }
        .stat-card { background:linear-gradient(135deg,rgba(30,41,59,.9) 0%,rgba(15,23,42,.9) 100%); padding:25px; border-radius:18px; border:1px solid rgba(96,165,250,.2); transition:all .3s; position:relative; overflow:hidden; }
        .stat-card::before { content:''; position:absolute; top:0; left:0; width:100%; height:4px; background:linear-gradient(90deg,#60a5fa,#a78bfa,#ec4899); }
        .stat-card:hover { transform:translateY(-5px); box-shadow:0 15px 35px rgba(0,0,0,.5); border-color:rgba(96,165,250,.5); }
        .stat-icon { width:60px; height:60px; border-radius:15px; display:flex; align-items:center; justify-content:center; font-size:1.8em; margin-bottom:15px; background:linear-gradient(135deg,rgba(96,165,250,.2),rgba(167,139,250,.2)); }
        .stat-label { color:#94a3b8; font-size:.9em; text-transform:uppercase; letter-spacing:1px; margin-bottom:10px; font-weight:600; }
        .stat-value { font-size:2.8em; font-weight:800; background:linear-gradient(135deg,#60a5fa,#a78bfa); -webkit-background-clip:text; -webkit-text-fill-color:transparent; line-height:1; margin-bottom:10px; }
        .stat-subtitle { color:#64748b; font-size:.85em; }

        /* Model card */
        .model-card { background:linear-gradient(135deg,rgba(167,139,250,.15) 0%,rgba(236,72,153,.15) 100%); padding:30px; border-radius:20px; border:2px solid rgba(167,139,250,.4); margin-bottom:30px; box-shadow:0 10px 30px rgba(167,139,250,.2); }
        .model-header { display:flex; align-items:center; gap:15px; margin-bottom:25px; }
        .model-header i { font-size:2.5em; color:#a78bfa; }
        .model-header h2 { font-size:1.6em; font-weight:700; }
        .model-metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:20px; }
        .model-metric { background:rgba(15,23,42,.6); padding:20px; border-radius:15px; border:1px solid rgba(167,139,250,.3); transition:all .3s; }
        .model-metric:hover { border-color:rgba(167,139,250,.6); transform:translateY(-3px); }
        .model-metric-label { color:#a78bfa; font-size:.8em; text-transform:uppercase; margin-bottom:10px; }
        .model-metric-value { font-size:1.8em; font-weight:700; color:#e4e7eb; }

        /* Analytics specific */
        .analytics-stat-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:20px; margin-bottom:30px; }
        .analytics-stat { background:linear-gradient(135deg,rgba(30,41,59,.9),rgba(15,23,42,.9)); border-radius:16px; padding:22px; border:1px solid rgba(96,165,250,.2); position:relative; overflow:hidden; transition:all .3s; }
        .analytics-stat::before { content:''; position:absolute; top:0; left:0; width:100%; height:3px; }
        .analytics-stat.blue::before { background:linear-gradient(90deg,#60a5fa,#3b82f6); }
        .analytics-stat.purple::before { background:linear-gradient(90deg,#a78bfa,#7c3aed); }
        .analytics-stat.green::before { background:linear-gradient(90deg,#34d399,#059669); }
        .analytics-stat.red::before { background:linear-gradient(90deg,#f87171,#dc2626); }
        .analytics-stat.orange::before { background:linear-gradient(90deg,#fb923c,#ea580c); }
        .analytics-stat.yellow::before { background:linear-gradient(90deg,#fbbf24,#d97706); }
        .analytics-stat:hover { transform:translateY(-4px); box-shadow:0 12px 30px rgba(0,0,0,.4); }
        .analytics-stat .as-icon { font-size:2em; margin-bottom:10px; }
        .analytics-stat .as-label { color:#94a3b8; font-size:.8em; text-transform:uppercase; letter-spacing:1px; }
        .analytics-stat .as-value { font-size:2.4em; font-weight:800; line-height:1.1; margin:6px 0; }
        .analytics-stat.blue .as-value { color:#60a5fa; }
        .analytics-stat.purple .as-value { color:#a78bfa; }
        .analytics-stat.green .as-value { color:#34d399; }
        .analytics-stat.red .as-value { color:#f87171; }
        .analytics-stat.orange .as-value { color:#fb923c; }
        .analytics-stat.yellow .as-value { color:#fbbf24; }

        /* Threat badges */
        .threat-badge { display:inline-block; padding:4px 12px; border-radius:999px; font-size:.75em; font-weight:700; letter-spacing:.5px; }
        .threat-BREACH { background:rgba(239,68,68,.25); color:#fca5a5; border:1px solid rgba(239,68,68,.5); }
        .threat-HIGH   { background:rgba(251,191,36,.2);  color:#fde68a; border:1px solid rgba(251,191,36,.4); }
        .threat-MEDIUM { background:rgba(251,146,60,.2);  color:#fed7aa; border:1px solid rgba(251,146,60,.4); }
        .threat-LOW    { background:rgba(96,165,250,.15); color:#bfdbfe; border:1px solid rgba(96,165,250,.3); }

        /* IP Table */
        .ip-table-wrap { overflow-x:auto; }
        table.ip-table { width:100%; border-collapse:collapse; font-size:.88em; }
        table.ip-table th { padding:14px 16px; text-align:left; color:#94a3b8; font-size:.78em; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid rgba(96,165,250,.15); background:rgba(15,23,42,.5); }
        table.ip-table td { padding:13px 16px; border-bottom:1px solid rgba(96,165,250,.08); vertical-align:middle; }
        table.ip-table tr:hover td { background:rgba(96,165,250,.05); cursor:pointer; }
        table.ip-table tr.selected td { background:rgba(96,165,250,.12); }
        .ip-cell { font-family:'Courier New',monospace; font-weight:700; color:#60a5fa; }

        /* Drilldown panel */
        #ip-drilldown { display:none; background:rgba(15,23,42,.95); border:1px solid rgba(96,165,250,.3); border-radius:16px; padding:25px; margin-top:20px; }
        #ip-drilldown.open { display:block; animation:slideIn .3s ease; }
        .drilldown-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; }
        .session-event { padding:10px 14px; border-radius:8px; margin-bottom:6px; font-size:.85em; border-left:3px solid; }
        .session-event.connect  { border-color:#60a5fa; background:rgba(96,165,250,.07); }
        .session-event.login_f  { border-color:#f87171; background:rgba(248,113,113,.07); }
        .session-event.login_s  { border-color:#34d399; background:rgba(52,211,153,.12); }
        .session-event.cmd      { border-color:#fbbf24; background:rgba(251,191,36,.07); }
        .session-event.closed   { border-color:#94a3b8; background:rgba(148,163,184,.05); }
        .session-event.other    { border-color:#a78bfa; background:rgba(167,139,250,.05); }

        /* Raw log table */
        .raw-log-table { width:100%; border-collapse:collapse; font-size:.82em; font-family:'Courier New',monospace; }
        .raw-log-table th { padding:10px 12px; text-align:left; color:#94a3b8; font-size:.75em; text-transform:uppercase; border-bottom:1px solid rgba(96,165,250,.15); background:rgba(15,23,42,.6); position:sticky; top:0; z-index:2; }
        .raw-log-table td { padding:9px 12px; border-bottom:1px solid rgba(96,165,250,.06); vertical-align:top; word-break:break-all; }
        .raw-log-table tr:hover td { background:rgba(96,165,250,.05); }
        .event-chip { display:inline-block; padding:2px 8px; border-radius:4px; font-size:.7em; font-weight:700; }
        .ec-connect  { background:rgba(96,165,250,.2);  color:#bfdbfe; }
        .ec-login_f  { background:rgba(248,113,113,.2); color:#fecaca; }
        .ec-login_s  { background:rgba(52,211,153,.2);  color:#a7f3d0; }
        .ec-cmd      { background:rgba(251,191,36,.2);  color:#fde68a; }
        .ec-closed   { background:rgba(148,163,184,.2); color:#e2e8f0; }
        .ec-other    { background:rgba(167,139,250,.2); color:#ddd6fe; }

        /* Filter chips */
        .filter-chips { display:flex; gap:8px; flex-wrap:wrap; }
        .chip { padding:6px 16px; border-radius:999px; border:1px solid rgba(96,165,250,.3); color:#94a3b8; font-size:.82em; cursor:pointer; transition:all .2s; }
        .chip:hover { border-color:#60a5fa; color:#60a5fa; }
        .chip.active { background:rgba(96,165,250,.2); border-color:#60a5fa; color:#60a5fa; font-weight:700; }

        /* Search */
        .search-input { background:rgba(15,23,42,.8); border:1px solid rgba(96,165,250,.3); padding:10px 16px; border-radius:10px; color:#e4e7eb; font-size:.9em; outline:none; width:100%; }
        .search-input:focus { border-color:#60a5fa; }

        /* Chart card */
        .chart-card { background:rgba(30,41,59,.8); padding:30px; border-radius:20px; border:1px solid rgba(96,165,250,.2); box-shadow:0 10px 30px rgba(0,0,0,.3); }
        .chart-header { display:flex; align-items:center; gap:12px; margin-bottom:25px; }
        .chart-header i { color:#60a5fa; font-size:1.4em; }
        .chart-header h3 { font-size:1.3em; font-weight:700; }

        ::-webkit-scrollbar { width:8px; }
        ::-webkit-scrollbar-track { background:rgba(15,23,42,.5); }
        ::-webkit-scrollbar-thumb { background:rgba(96,165,250,.4); border-radius:4px; }

        @media(max-width:768px) { .header { flex-direction:column; gap:20px; } .stats-grid { grid-template-columns:1fr; } }
    </style>
</head>
<body>
    <div class="loading-overlay" id="loadingOverlay">
        <div class="spinner"></div>
        <div class="loading-text"><i class="fas fa-brain"></i> Initializing Advanced IDS Platform</div>
        <div style="color:#94a3b8;margin-top:10px;">Loading ML models and connecting to honeypot...</div>
    </div>

    <div class="container">
        <div class="header">
            <div>
                <h1><i class="fas fa-shield-halved"></i> Advanced IDS Dashboard</h1>
                <div class="header-subtitle">
                    Enterprise Security Operations Center with Enhanced Control
                    <span class="badge badge-ml">ML-POWERED</span>
                    <span class="badge badge-pro">REAL-TIME</span>
                </div>
            </div>
            <div style="display:flex;gap:12px;align-items:center;">
                <div class="status-pill initializing" id="statusPill">
                    <div class="status-dot initializing" id="statusDot"></div>
                    <div>
                        <div style="font-weight:600;font-size:1.1em;" id="statusText">Initializing</div>
                        <div style="font-size:.85em;color:#94a3b8;">Model: <span id="current-model-display">Loading...</span></div>
                    </div>
                </div>
                <button class="btn-export" onclick="exportData()"><i class="fas fa-download"></i> Export Report</button>
                <button class="btn-logout" onclick="logout()"><i class="fas fa-right-from-bracket"></i> Logout</button>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="switchTab('dashboard',this)"><i class="fas fa-chart-line"></i> Dashboard</div>
            <div class="tab" onclick="switchTab('control',this)"><i class="fas fa-sliders"></i> Control Center</div>
            <div class="tab" onclick="switchTab('analytics',this);loadAnalytics();"><i class="fas fa-magnifying-glass-chart"></i> Honeypot Analytics</div>
        </div>

        <!-- ══════════════════════ DASHBOARD TAB ══════════════════════ -->
        <div id="dashboard-tab" class="tab-content active">
            <div class="model-card">
                <div class="model-header">
                    <i class="fas fa-brain"></i>
                    <div>
                        <h2>Machine Learning Engine</h2>
                        <div style="color:#94a3b8;font-size:.95em;margin-top:5px;">Powered by trained NSL-KDD/UNSW-NB15 detection models</div>
                    </div>
                </div>
                <div class="model-metrics">
                    <div class="model-metric"><div class="model-metric-label">Algorithm</div><div class="model-metric-value" id="model-name">Loading...</div></div>
                    <div class="model-metric"><div class="model-metric-label">Accuracy</div><div class="model-metric-value" id="model-accuracy">--%</div></div>
                    <div class="model-metric"><div class="model-metric-label">F1-Score</div><div class="model-metric-value" id="model-f1">--%</div></div>
                    <div class="model-metric"><div class="model-metric-label">Avg Confidence</div><div class="model-metric-value" id="avg-confidence">--%</div></div>
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-card"><div class="stat-icon"><i class="fas fa-chart-line"></i></div><div class="stat-label">Total Events</div><div class="stat-value" id="total-events">0</div><div class="stat-subtitle" id="events-per-min">0 events/min</div></div>
                <div class="stat-card"><div class="stat-icon"><i class="fas fa-exclamation-triangle"></i></div><div class="stat-label">Attacks Detected</div><div class="stat-value" id="attacks-detected">0</div><div class="stat-subtitle" id="attack-rate">0% attack rate</div></div>
                <div class="stat-card"><div class="stat-icon"><i class="fas fa-network-wired"></i></div><div class="stat-label">Unique Attackers</div><div class="stat-value" id="unique-attackers">0</div><div class="stat-subtitle">distinct source IPs</div></div>
                <div class="stat-card"><div class="stat-icon"><i class="fas fa-robot"></i></div><div class="stat-label">ML Predictions</div><div class="stat-value" id="ml-predictions">0</div><div class="stat-subtitle" id="ml-prediction-rate">0 normal</div></div>
            </div>

            <div class="charts-grid" style="display:grid;grid-template-columns:repeat(2,1fr);gap:25px;margin-bottom:30px;">
                <div class="chart-card"><div class="chart-header"><i class="fas fa-chart-area"></i><h3>Attack Timeline (24h)</h3></div><canvas id="timelineChart" style="max-height:350px;"></canvas></div>
                <div class="chart-card"><div class="chart-header"><i class="fas fa-chart-pie"></i><h3>Attack Types</h3></div><canvas id="attackTypesChart" style="max-height:350px;"></canvas></div>
                <div class="chart-card"><div class="chart-header"><i class="fas fa-chart-bar"></i><h3>Severity Distribution</h3></div><canvas id="severityChart" style="max-height:350px;"></canvas></div>
                <div class="chart-card"><div class="chart-header"><i class="fas fa-percentage"></i><h3>ML Confidence Scores</h3></div><canvas id="confidenceChart" style="max-height:350px;"></canvas></div>
                <div class="chart-card"><div class="chart-header"><i class="fas fa-globe"></i><h3>Geographic Distribution</h3></div><canvas id="geoChart" style="max-height:350px;"></canvas></div>
            </div>

            <div class="incidents-card" style="background:rgba(30,41,59,.8);padding:30px;border-radius:20px;border:1px solid rgba(96,165,250,.2);">
                <div class="chart-header" style="margin-bottom:25px;"><i class="fas fa-bell" style="color:#60a5fa;font-size:1.4em;"></i><h3 style="font-size:1.3em;font-weight:700;">Live Incident Feed</h3></div>
                <div id="incident-list" style="max-height:600px;overflow-y:auto;"><div style="text-align:center;padding:40px;color:#94a3b8;"><i class="fas fa-spinner fa-spin"></i> Waiting for IDS initialization...</div></div>
            </div>
        </div>

        <!-- ══════════════════════ CONTROL TAB ══════════════════════ -->
        <div id="control-tab" class="tab-content">
            <!-- Model Selection -->
            <div class="control-section">
                <div class="control-header"><i class="fas fa-brain"></i><div><h2>ML Model Selection</h2><div style="color:#94a3b8;font-size:.95em;margin-top:5px;">Switch between different machine learning models in real-time</div></div></div>
                <div class="model-grid" id="model-selection">
                    <div class="model-option" onclick="selectModel('Random Forest')"><div class="model-name">🌲 Random Forest</div><div class="model-desc">Ensemble tree-based classifier with high accuracy</div></div>
                    <div class="model-option" onclick="selectModel('XGBoost')"><div class="model-name">⚡ XGBoost</div><div class="model-desc">Gradient boosting with excellent performance</div></div>
                    <div class="model-option" onclick="selectModel('Decision Tree')"><div class="model-name">🌳 Decision Tree</div><div class="model-desc">Simple rule-based tree classifier</div></div>
                    <div class="model-option" onclick="selectModel('KNN')"><div class="model-name">📍 K-Nearest Neighbors</div><div class="model-desc">Distance-based classifier</div></div>
                    <div class="model-option" onclick="selectModel('Logistic Regression')"><div class="model-name">📈 Logistic Regression</div><div class="model-desc">Linear probabilistic classifier</div></div>
                    <div class="model-option" onclick="selectModel('LightGBM')"><div class="model-name">💡 LightGBM</div><div class="model-desc">Fast gradient boosting framework</div></div>
                </div>
            </div>

            <!-- Model Performance -->
            <div class="control-section">
                <div class="control-header"><i class="fas fa-chart-bar"></i><div><h2>Model Performance Comparison</h2><div style="color:#94a3b8;font-size:.95em;margin-top:5px;">Real-time comparison of different ML models</div></div></div>
                <div id="model-performance-list" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;"><div style="text-align:center;padding:40px;color:#94a3b8;"><i class="fas fa-spinner fa-spin"></i> Loading model performance data...</div></div>
            </div>

            <!-- Attack Simulation -->
            <div class="control-section">
                <div class="control-header"><i class="fas fa-bomb"></i><div><h2>Attack Simulation</h2><div style="color:#94a3b8;font-size:.95em;margin-top:5px;">Test IDS with simulated attacks</div></div></div>
                <div class="attack-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-top:20px;">
                    <!-- attack cards preserved exactly from original -->
                    <div class="attack-card" style="background:linear-gradient(135deg,rgba(15,23,42,.9),rgba(30,41,59,.9));padding:25px;border-radius:15px;border:2px solid rgba(239,68,68,.3);transition:all .3s;">
                        <div style="width:60px;height:60px;background:linear-gradient(135deg,rgba(239,68,68,.3),rgba(220,38,38,.3));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.8em;color:#ef4444;margin-bottom:15px;"><i class="fas fa-server"></i></div>
                        <div style="font-size:1.3em;font-weight:700;margin-bottom:10px;">DDoS Attack</div>
                        <div style="color:#94a3b8;font-size:.85em;margin-bottom:20px;line-height:1.6;">Simulate distributed denial-of-service attack with high packet volume</div>
                        <div style="display:flex;gap:10px;align-items:center;">
                            <input type="number" id="ddos-count" value="100" min="1" max="1000" style="flex:1;background:rgba(15,23,42,.8);border:1px solid rgba(96,165,250,.3);padding:10px 15px;border-radius:8px;color:#e4e7eb;font-size:.9em;">
                            <button onclick="simulateAttack('ddos',document.getElementById('ddos-count').value)" style="background:linear-gradient(135deg,#ef4444,#dc2626);color:white;border:none;padding:10px 20px;border-radius:8px;font-weight:600;cursor:pointer;white-space:nowrap;"><i class="fas fa-play"></i> Simulate</button>
                        </div>
                    </div>
                    <div class="attack-card" style="background:linear-gradient(135deg,rgba(15,23,42,.9),rgba(30,41,59,.9));padding:25px;border-radius:15px;border:2px solid rgba(239,68,68,.3);">
                        <div style="width:60px;height:60px;background:linear-gradient(135deg,rgba(239,68,68,.3),rgba(220,38,38,.3));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.8em;color:#ef4444;margin-bottom:15px;"><i class="fas fa-database"></i></div>
                        <div style="font-size:1.3em;font-weight:700;margin-bottom:10px;">SQL Injection</div>
                        <div style="color:#94a3b8;font-size:.85em;margin-bottom:20px;line-height:1.6;">Simulate SQL injection attempts with malicious payloads</div>
                        <div style="display:flex;gap:10px;align-items:center;">
                            <input type="number" id="sql-count" value="10" min="1" max="100" style="flex:1;background:rgba(15,23,42,.8);border:1px solid rgba(96,165,250,.3);padding:10px 15px;border-radius:8px;color:#e4e7eb;font-size:.9em;">
                            <button onclick="simulateAttack('sql_injection',document.getElementById('sql-count').value)" style="background:linear-gradient(135deg,#ef4444,#dc2626);color:white;border:none;padding:10px 20px;border-radius:8px;font-weight:600;cursor:pointer;"><i class="fas fa-play"></i> Simulate</button>
                        </div>
                    </div>
                    <div class="attack-card" style="background:linear-gradient(135deg,rgba(15,23,42,.9),rgba(30,41,59,.9));padding:25px;border-radius:15px;border:2px solid rgba(239,68,68,.3);">
                        <div style="width:60px;height:60px;background:linear-gradient(135deg,rgba(239,68,68,.3),rgba(220,38,38,.3));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.8em;color:#ef4444;margin-bottom:15px;"><i class="fas fa-key"></i></div>
                        <div style="font-size:1.3em;font-weight:700;margin-bottom:10px;">Brute Force</div>
                        <div style="color:#94a3b8;font-size:.85em;margin-bottom:20px;line-height:1.6;">Simulate password brute-force attack on SSH service</div>
                        <div style="display:flex;gap:10px;align-items:center;">
                            <input type="number" id="brute-count" value="50" min="1" max="200" style="flex:1;background:rgba(15,23,42,.8);border:1px solid rgba(96,165,250,.3);padding:10px 15px;border-radius:8px;color:#e4e7eb;font-size:.9em;">
                            <button onclick="simulateAttack('brute_force',document.getElementById('brute-count').value)" style="background:linear-gradient(135deg,#ef4444,#dc2626);color:white;border:none;padding:10px 20px;border-radius:8px;font-weight:600;cursor:pointer;"><i class="fas fa-play"></i> Simulate</button>
                        </div>
                    </div>
                    <div class="attack-card" style="background:linear-gradient(135deg,rgba(15,23,42,.9),rgba(30,41,59,.9));padding:25px;border-radius:15px;border:2px solid rgba(239,68,68,.3);">
                        <div style="width:60px;height:60px;background:linear-gradient(135deg,rgba(239,68,68,.3),rgba(220,38,38,.3));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.8em;color:#ef4444;margin-bottom:15px;"><i class="fas fa-terminal"></i></div>
                        <div style="font-size:1.3em;font-weight:700;margin-bottom:10px;">Command Injection</div>
                        <div style="color:#94a3b8;font-size:.85em;margin-bottom:20px;line-height:1.6;">Simulate OS command injection attempts</div>
                        <div style="display:flex;gap:10px;align-items:center;">
                            <input type="number" id="cmd-count" value="15" min="1" max="100" style="flex:1;background:rgba(15,23,42,.8);border:1px solid rgba(96,165,250,.3);padding:10px 15px;border-radius:8px;color:#e4e7eb;font-size:.9em;">
                            <button onclick="simulateAttack('command_injection',document.getElementById('cmd-count').value)" style="background:linear-gradient(135deg,#ef4444,#dc2626);color:white;border:none;padding:10px 20px;border-radius:8px;font-weight:600;cursor:pointer;"><i class="fas fa-play"></i> Simulate</button>
                        </div>
                    </div>
                    <div class="attack-card" style="background:linear-gradient(135deg,rgba(15,23,42,.9),rgba(30,41,59,.9));padding:25px;border-radius:15px;border:2px solid rgba(239,68,68,.3);">
                        <div style="width:60px;height:60px;background:linear-gradient(135deg,rgba(239,68,68,.3),rgba(220,38,38,.3));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.8em;color:#ef4444;margin-bottom:15px;"><i class="fas fa-virus"></i></div>
                        <div style="font-size:1.3em;font-weight:700;margin-bottom:10px;">Malware Intrusion</div>
                        <div style="color:#94a3b8;font-size:.85em;margin-bottom:20px;line-height:1.6;">Simulate malware intrusion attempts</div>
                        <div style="display:flex;gap:10px;align-items:center;">
                            <input type="number" id="malware-count" value="20" min="1" max="100" style="flex:1;background:rgba(15,23,42,.8);border:1px solid rgba(96,165,250,.3);padding:10px 15px;border-radius:8px;color:#e4e7eb;font-size:.9em;">
                            <button onclick="simulateAttack('malware_intrusion',document.getElementById('malware-count').value)" style="background:linear-gradient(135deg,#ef4444,#dc2626);color:white;border:none;padding:10px 20px;border-radius:8px;font-weight:600;cursor:pointer;"><i class="fas fa-play"></i> Simulate</button>
                        </div>
                    </div>
                    <div class="attack-card" style="background:linear-gradient(135deg,rgba(15,23,42,.9),rgba(30,41,59,.9));padding:25px;border-radius:15px;border:2px solid rgba(239,68,68,.3);">
                        <div style="width:60px;height:60px;background:linear-gradient(135deg,rgba(239,68,68,.3),rgba(220,38,38,.3));border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.8em;color:#ef4444;margin-bottom:15px;"><i class="fas fa-bug"></i></div>
                        <div style="font-size:1.3em;font-weight:700;margin-bottom:10px;">Zero-Day Exploit</div>
                        <div style="color:#94a3b8;font-size:.85em;margin-bottom:20px;line-height:1.6;">Simulate unknown vulnerability exploitation</div>
                        <div style="display:flex;gap:10px;align-items:center;">
                            <input type="number" id="zeroday-count" value="5" min="1" max="50" style="flex:1;background:rgba(15,23,42,.8);border:1px solid rgba(96,165,250,.3);padding:10px 15px;border-radius:8px;color:#e4e7eb;font-size:.9em;">
                            <button onclick="simulateAttack('zero_day',document.getElementById('zeroday-count').value)" style="background:linear-gradient(135deg,#ef4444,#dc2626);color:white;border:none;padding:10px 20px;border-radius:8px;font-weight:600;cursor:pointer;"><i class="fas fa-play"></i> Simulate</button>
                        </div>
                    </div>
                </div>
                <div id="simulation-log" style="background:rgba(15,23,42,.9);padding:20px;border-radius:12px;border:1px solid rgba(96,165,250,.2);max-height:300px;overflow-y:auto;font-family:'Courier New',monospace;font-size:.85em;margin-top:20px;"><div style="color:#64748b;">Simulation log ready...</div></div>
            </div>

            <!-- IP Blacklist -->
            <div class="control-section">
                <div class="control-header"><i class="fas fa-ban"></i><div><h2>IP Blacklist Management</h2><div style="color:#94a3b8;font-size:.95em;margin-top:5px;">Manage blacklisted IP addresses</div></div></div>
                <div style="display:flex;gap:10px;margin-bottom:20px;">
                    <input type="text" id="blacklist-ip-input" placeholder="Enter IP address (e.g., 192.168.1.100)" style="flex:1;background:rgba(15,23,42,.8);border:1px solid rgba(96,165,250,.3);padding:12px 20px;border-radius:10px;color:#e4e7eb;font-size:1em;">
                    <button onclick="addToBlacklist()" style="background:linear-gradient(135deg,#ef4444,#dc2626);color:white;border:none;padding:12px 30px;border-radius:10px;font-weight:600;cursor:pointer;white-space:nowrap;"><i class="fas fa-plus"></i> Add to Blacklist</button>
                </div>
                <div id="blacklist-container" style="max-height:400px;overflow-y:auto;"><div style="text-align:center;padding:40px;color:#94a3b8;"><i class="fas fa-shield-alt"></i> No blacklisted IPs yet</div></div>
            </div>

            <!-- Top Attackers -->
            <div class="control-section">
                <div class="control-header"><i class="fas fa-user-secret"></i><div><h2>Top Attackers</h2><div style="color:#94a3b8;font-size:.95em;margin-top:5px;">Most active attacking IP addresses</div></div></div>
                <div id="top-attackers-list"><div style="text-align:center;padding:40px;color:#94a3b8;"><i class="fas fa-spinner fa-spin"></i> Loading attacker data...</div></div>
            </div>
        </div>

        <!-- ══════════════════════ ANALYTICS TAB ══════════════════════ -->
        <div id="analytics-tab" class="tab-content">

            <!-- Summary Stats -->
            <div class="analytics-stat-grid" id="analytics-summary">
                <div class="analytics-stat blue"><div class="as-icon">📡</div><div class="as-label">Total Events</div><div class="as-value" id="as-total">—</div></div>
                <div class="analytics-stat purple"><div class="as-icon">🔌</div><div class="as-label">Sessions</div><div class="as-value" id="as-sessions">—</div></div>
                <div class="analytics-stat orange"><div class="as-icon">🔑</div><div class="as-label">Login Attempts</div><div class="as-value" id="as-logins">—</div></div>
                <div class="analytics-stat yellow"><div class="as-icon">💻</div><div class="as-label">Commands Run</div><div class="as-value" id="as-commands">—</div></div>
                <div class="analytics-stat green"><div class="as-icon">🌐</div><div class="as-label">Unique IPs</div><div class="as-value" id="as-ips">—</div></div>
                <div class="analytics-stat red"><div class="as-icon">🚨</div><div class="as-label">Successful Logins</div><div class="as-value" id="as-success">—</div></div>
            </div>

            <!-- Charts Row -->
            <div style="display:grid;grid-template-columns:2fr 1fr;gap:25px;margin-bottom:25px;">
                <div class="chart-card">
                    <div class="chart-header"><i class="fas fa-chart-area"></i><h3>Events Over Time</h3></div>
                    <canvas id="an-timeline" style="max-height:280px;"></canvas>
                </div>
                <div class="chart-card">
                    <div class="chart-header"><i class="fas fa-chart-pie"></i><h3>Event Type Breakdown</h3></div>
                    <canvas id="an-event-types" style="max-height:280px;"></canvas>
                </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:25px;margin-bottom:25px;">
                <div class="chart-card">
                    <div class="chart-header"><i class="fas fa-chart-bar"></i><h3>Top Attacker IPs (by activity)</h3></div>
                    <canvas id="an-top-ips" style="max-height:300px;"></canvas>
                </div>
                <div class="chart-card">
                    <div class="chart-header"><i class="fas fa-key"></i><h3>Top Passwords Tried</h3></div>
                    <canvas id="an-top-passwords" style="max-height:300px;"></canvas>
                </div>
            </div>

            <!-- IP Intelligence Table -->
            <div class="control-section" style="margin-bottom:25px;">
                <div class="control-header"><i class="fas fa-table"></i><div><h2>IP Intelligence</h2><div style="color:#94a3b8;font-size:.95em;margin-top:5px;">Click any row to see full session timeline</div></div></div>
                <div class="ip-table-wrap">
                    <table class="ip-table" id="ip-intel-table">
                        <thead>
                            <tr>
                                <th>Threat</th>
                                <th>IP Address</th>
                                <th>Sessions</th>
                                <th>Login Attempts</th>
                                <th>Successes</th>
                                <th>Commands</th>
                                <th>First Seen</th>
                                <th>Last Seen</th>
                                <th>Top Passwords</th>
                            </tr>
                        </thead>
                        <tbody id="ip-intel-body">
                            <tr><td colspan="9" style="text-align:center;padding:40px;color:#94a3b8;"><i class="fas fa-spinner fa-spin"></i> Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
                <!-- Drilldown panel -->
                <div id="ip-drilldown">
                    <div class="drilldown-header">
                        <div>
                            <span style="font-size:1.1em;font-weight:700;color:#60a5fa;" id="drilldown-ip">—</span>
                            <span id="drilldown-threat" style="margin-left:10px;"></span>
                        </div>
                        <button onclick="closeDrilldown()" style="background:rgba(96,165,250,.15);border:1px solid rgba(96,165,250,.3);color:#60a5fa;padding:6px 16px;border-radius:8px;cursor:pointer;font-size:.85em;">✕ Close</button>
                    </div>
                    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px;" id="drilldown-stats"></div>
                    <div style="font-weight:600;color:#94a3b8;font-size:.85em;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;">Session Timeline</div>
                    <div id="drilldown-events" style="max-height:350px;overflow-y:auto;"></div>
                </div>
            </div>

            <!-- Raw Event Log -->
            <div class="control-section">
                <div class="control-header"><i class="fas fa-list"></i><div><h2>Raw Event Log</h2><div style="color:#94a3b8;font-size:.95em;margin-top:5px;">Full cowrie event stream — search and filter</div></div></div>
                <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;">
                    <input type="text" id="raw-search" class="search-input" placeholder="🔍 Search events, IPs, commands..." style="max-width:320px;" oninput="loadRawLogs()">
                    <div class="filter-chips" id="filter-chips">
                        <span class="chip active" data-filter="" onclick="setFilter(this,'')">All</span>
                        <span class="chip" data-filter="session.connect" onclick="setFilter(this,'session.connect')">Connect</span>
                        <span class="chip" data-filter="login.failed" onclick="setFilter(this,'login.failed')">Login Failed</span>
                        <span class="chip" data-filter="login.success" onclick="setFilter(this,'login.success')">✅ Success</span>
                        <span class="chip" data-filter="command.input" onclick="setFilter(this,'command.input')">Commands</span>
                        <span class="chip" data-filter="session.closed" onclick="setFilter(this,'session.closed')">Closed</span>
                    </div>
                </div>
                <div style="max-height:500px;overflow-y:auto;border-radius:12px;border:1px solid rgba(96,165,250,.12);">
                    <table class="raw-log-table">
                        <thead>
                            <tr>
                                <th style="width:170px;">Timestamp</th>
                                <th style="width:140px;">Event</th>
                                <th style="width:130px;">Source IP</th>
                                <th style="width:110px;">Session</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody id="raw-log-body">
                            <tr><td colspan="5" style="text-align:center;padding:30px;color:#94a3b8;"><i class="fas fa-spinner fa-spin"></i> Loading logs...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

        </div><!-- /analytics-tab -->
    </div><!-- /container -->

<script src="/static/dashboard.js"></script>
<script>
// ══════════════════════════════════════════════════
//  LOGOUT FIX — use window.location for hard redirect
// ══════════════════════════════════════════════════
function logout() {
    if (!confirm('Disconnect from honeypot and logout?')) return;
    window.location.href = '/logout';
}

// ══════════════════════════════════════════════════
//  TAB SWITCHING (preserves original behaviour)
// ══════════════════════════════════════════════════
function switchTab(name, el) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById(name + '-tab').classList.add('active');
    el.classList.add('active');
}

// ══════════════════════════════════════════════════
//  ANALYTICS CHARTS STATE
// ══════════════════════════════════════════════════
let anCharts = {};
let activeFilter = '';
let analyticsLoaded = false;

function loadAnalytics() {
    if (analyticsLoaded) return;
    analyticsLoaded = true;
    Promise.all([
        fetch('/api/analytics/summary').then(r=>r.json()),
        fetch('/api/analytics/timeline').then(r=>r.json()),
        fetch('/api/analytics/event_types').then(r=>r.json()),
        fetch('/api/analytics/top_ips').then(r=>r.json()),
        fetch('/api/analytics/top_passwords').then(r=>r.json()),
        fetch('/api/analytics/ip_table').then(r=>r.json()),
    ]).then(([summary, timeline, eventTypes, topIps, topPwds, ipTable]) => {
        renderSummary(summary);
        renderTimelineChart(timeline);
        renderEventTypesChart(eventTypes);
        renderTopIpsChart(topIps);
        renderTopPasswordsChart(topPwds);
        renderIpTable(ipTable);
        loadRawLogs();
    }).catch(err => console.error('Analytics load error:', err));
}

function renderSummary(s) {
    document.getElementById('as-total').textContent    = (s.total_events||0).toLocaleString();
    document.getElementById('as-sessions').textContent = (s.total_sessions||0).toLocaleString();
    document.getElementById('as-logins').textContent   = (s.login_attempts||0).toLocaleString();
    document.getElementById('as-commands').textContent = (s.commands_run||0).toLocaleString();
    document.getElementById('as-ips').textContent      = (s.unique_ips||0).toLocaleString();
    document.getElementById('as-success').textContent  = (s.successful_logins||0).toLocaleString();
}

const CHART_COLORS = ['#60a5fa','#a78bfa','#f87171','#34d399','#fbbf24','#fb923c','#38bdf8','#e879f9','#4ade80','#f472b6'];

function mkChart(id, type, labels, datasets, opts={}) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    if (anCharts[id]) { anCharts[id].destroy(); }
    anCharts[id] = new Chart(ctx, {
        type, data: { labels, datasets },
        options: {
            responsive: true, maintainAspectRatio: true,
            plugins: { legend: { labels: { color:'#94a3b8', font:{size:12} } }, tooltip: { mode:'index', intersect:false } },
            scales: type === 'bar' || type === 'line' ? {
                x: { ticks:{color:'#64748b',maxRotation:45}, grid:{color:'rgba(96,165,250,.08)'} },
                y: { ticks:{color:'#64748b'}, grid:{color:'rgba(96,165,250,.08)'}, beginAtZero:true }
            } : {},
            ...opts
        }
    });
}

function renderTimelineChart(data) {
    const labels = data.map(d => d.time.replace(' ', ' '));
    const counts = data.map(d => d.count);
    mkChart('an-timeline','line', labels, [{
        label:'Events', data:counts, borderColor:'#60a5fa', backgroundColor:'rgba(96,165,250,.15)',
        fill:true, tension:.4, pointRadius:3, pointHoverRadius:6
    }]);
}

function renderEventTypesChart(data) {
    const labels = data.map(d => d.type.replace('_',' '));
    const counts = data.map(d => d.count);
    mkChart('an-event-types','doughnut', labels, [{
        data:counts, backgroundColor: CHART_COLORS.slice(0, labels.length),
        borderColor:'rgba(15,23,42,.5)', borderWidth:2, hoverOffset:8
    }]);
}

function renderTopIpsChart(data) {
    const top10 = data.slice(0,10);
    const labels = top10.map(d => d.ip);
    const logins = top10.map(d => d.login_attempts);
    const cmds   = top10.map(d => d.commands);
    mkChart('an-top-ips','bar', labels, [
        { label:'Login Attempts', data:logins, backgroundColor:'rgba(248,113,113,.7)', borderRadius:4 },
        { label:'Commands',       data:cmds,   backgroundColor:'rgba(251,191,36,.7)',  borderRadius:4 }
    ]);
}

function renderTopPasswordsChart(data) {
    const labels = data.map(d => d.password.length > 20 ? d.password.slice(0,20)+'…' : d.password);
    const counts = data.map(d => d.count);
    mkChart('an-top-passwords','bar', labels, [{
        label:'Times Tried', data:counts, backgroundColor:'rgba(167,139,250,.7)', borderRadius:4
    }]);
}

// ── IP Table ───────────────────────────────────────
function renderIpTable(rows) {
    const tbody = document.getElementById('ip-intel-body');
    if (!rows.length) { tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:30px;color:#94a3b8;">No data in log file</td></tr>'; return; }
    tbody.innerHTML = rows.map(r => `
        <tr onclick="drilldownIp('${r.ip}',this)">
            <td><span class="threat-badge threat-${r.threat}">${r.threat}</span></td>
            <td class="ip-cell">${r.ip}</td>
            <td>${r.sessions}</td>
            <td>${r.login_attempts}</td>
            <td style="color:${r.successes>0?'#f87171':'#64748b'};font-weight:${r.successes>0?700:400};">${r.successes}</td>
            <td>${r.commands}</td>
            <td style="color:#64748b;font-size:.82em;">${r.first_seen ? new Date(r.first_seen).toLocaleString() : '—'}</td>
            <td style="color:#64748b;font-size:.82em;">${r.last_seen  ? new Date(r.last_seen).toLocaleString()  : '—'}</td>
            <td style="font-family:'Courier New',monospace;font-size:.8em;color:#a78bfa;">${r.top_passwords.slice(0,2).map(p=>p.pwd).join(', ') || '—'}</td>
        </tr>`).join('');
}

// ── IP Drilldown ───────────────────────────────────
function drilldownIp(ip, row) {
    document.querySelectorAll('#ip-intel-body tr').forEach(r=>r.classList.remove('selected'));
    row.classList.add('selected');
    fetch(`/api/analytics/ip_detail?ip=${encodeURIComponent(ip)}`)
        .then(r=>r.json()).then(data => {
            const d = document.getElementById('ip-drilldown');
            d.classList.add('open');
            document.getElementById('drilldown-ip').textContent = ip;
            document.getElementById('drilldown-threat').innerHTML = `<span class="threat-badge threat-${data.info.threat}">${data.info.threat}</span>`;
            const i = data.info;
            document.getElementById('drilldown-stats').innerHTML = `
                <div style="background:rgba(96,165,250,.1);border-radius:10px;padding:14px;text-align:center;"><div style="color:#94a3b8;font-size:.75em;text-transform:uppercase;">Sessions</div><div style="font-size:1.8em;font-weight:700;color:#60a5fa;">${i.sessions}</div></div>
                <div style="background:rgba(248,113,113,.1);border-radius:10px;padding:14px;text-align:center;"><div style="color:#94a3b8;font-size:.75em;text-transform:uppercase;">Login Attempts</div><div style="font-size:1.8em;font-weight:700;color:#f87171;">${i.login_attempts}</div></div>
                <div style="background:rgba(52,211,153,.1);border-radius:10px;padding:14px;text-align:center;"><div style="color:#94a3b8;font-size:.75em;text-transform:uppercase;">Successes</div><div style="font-size:1.8em;font-weight:700;color:#34d399;">${i.successes}</div></div>
                <div style="background:rgba(251,191,36,.1);border-radius:10px;padding:14px;text-align:center;"><div style="color:#94a3b8;font-size:.75em;text-transform:uppercase;">Commands</div><div style="font-size:1.8em;font-weight:700;color:#fbbf24;">${i.commands}</div></div>`;
            const evtDiv = document.getElementById('drilldown-events');
            evtDiv.innerHTML = (data.events||[]).map(e => {
                let cls='other', icon='fa-circle-info', detail='';
                const eid = e.eventid||'';
                if (eid.includes('session.connect')) { cls='connect'; icon='fa-plug'; detail=`→ session ${e.session}`; }
                else if (eid.includes('login.failed'))  { cls='login_f'; icon='fa-xmark'; detail=`${e.username||'?'} / ${e.password||'?'}`; }
                else if (eid.includes('login.success')) { cls='login_s'; icon='fa-check'; detail=`✅ ${e.username} / ${e.password}`; }
                else if (eid.includes('command.input')) { cls='cmd';     icon='fa-terminal'; detail=`<code style="color:#fbbf24;">${(e.input||'').replace(/</g,'&lt;')}</code>`; }
                else if (eid.includes('session.closed')){ cls='closed';  icon='fa-plug-circle-xmark'; detail=e.message||''; }
                const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '';
                return `<div class="session-event ${cls}"><span style="color:#64748b;font-size:.78em;margin-right:10px;">${ts}</span><i class="fas ${icon}" style="margin-right:8px;"></i><span style="color:#94a3b8;font-size:.82em;margin-right:8px;">${eid}</span>${detail}</div>`;
            }).join('') || '<div style="color:#64748b;padding:20px;text-align:center;">No events found for this IP</div>';
            d.scrollIntoView({behavior:'smooth',block:'nearest'});
        });
}

function closeDrilldown() {
    document.getElementById('ip-drilldown').classList.remove('open');
    document.querySelectorAll('#ip-intel-body tr').forEach(r=>r.classList.remove('selected'));
}

// ── Raw Logs ───────────────────────────────────────
function setFilter(el, filter) {
    document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
    el.classList.add('active');
    activeFilter = filter;
    loadRawLogs();
}

function eventClass(eid) {
    if (eid.includes('session.connect')) return 'ec-connect';
    if (eid.includes('login.failed'))   return 'ec-login_f';
    if (eid.includes('login.success'))  return 'ec-login_s';
    if (eid.includes('command.input'))  return 'ec-cmd';
    if (eid.includes('session.closed')) return 'ec-closed';
    return 'ec-other';
}

function loadRawLogs() {
    const search = (document.getElementById('raw-search')||{}).value || '';
    const url = `/api/analytics/raw_logs?limit=200&event_type=${encodeURIComponent(activeFilter)}&search=${encodeURIComponent(search)}`;
    fetch(url).then(r=>r.json()).then(rows => {
        const tbody = document.getElementById('raw-log-body');
        if (!rows.length) { tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:30px;color:#64748b;">No matching events</td></tr>'; return; }
        tbody.innerHTML = rows.map(e => {
            const ts = e.timestamp ? new Date(e.timestamp).toLocaleString() : '—';
            const eid = e.eventid||'';
            const chip = `<span class="event-chip ${eventClass(eid)}">${eid.split('.').slice(-1)[0]}</span>`;
            let detail = '';
            if (e.input)    detail = `<span style="color:#fbbf24;">$ ${e.input}</span>`;
            else if (e.username && e.password) detail = `<span style="color:#94a3b8;">${e.username}</span> / <span style="color:#a78bfa;">${e.password}</span>`;
            else if (e.message) detail = `<span style="color:#64748b;">${String(e.message).slice(0,120)}</span>`;
            return `<tr>
                <td style="color:#64748b;white-space:nowrap;">${ts}</td>
                <td>${chip}</td>
                <td class="ip-cell">${e.src_ip||'—'}</td>
                <td style="color:#64748b;font-size:.8em;">${(e.session||'—').slice(0,12)}</td>
                <td>${detail}</td>
            </tr>`;
        }).join('');
    }).catch(()=>{});
}
</script>
</body>
</html>"""