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


            @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }




    /* Top Attackers Container */
#top-attackers-list {
    display: flex;
    flex-direction: column;
    gap: 14px;
}

/* Card */
.top-attacker-item {
    background: linear-gradient(145deg, rgba(15,23,42,0.9), rgba(2,6,23,0.9));
    border: 1px solid rgba(148,163,184,0.15);
    border-radius: 14px;
    padding: 16px 18px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.45);
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

/* Hover effect */
.top-attacker-item:hover {
    transform: translateY(-3px) scale(1.01);
    box-shadow: 0 20px 45px rgba(0,0,0,0.6);
}

/* Animated glow strip */
.top-attacker-item::before {
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    height: 100%;
    width: 4px;
    background: linear-gradient(to bottom, #22d3ee, #6366f1);
}

/* IP row */
.attacker-ip {
    font-size: 15px;
    font-weight: 600;
    color: #e5e7eb;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

/* Country badge */
.country-badge {
    background: rgba(99,102,241,0.15);
    color: #a5b4fc;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
}

/* Stats row */
.attacker-stats {
    display: flex;
    flex-wrap: wrap;
    gap: 14px;
    margin-top: 10px;
    font-size: 13px;
}

/* Stat items */
.stat {
    display: flex;
    align-items: center;
    gap: 6px;
    color: #cbd5f5;
}

/* Severity colors */
.stat.critical {
    color: #f87171;
    text-shadow: 0 0 10px rgba(248,113,113,0.4);
}

.stat.high {
    color: #fbbf24;
    text-shadow: 0 0 10px rgba(251,191,36,0.35);
}

/* Blacklist badge */
.blacklisted {
    background: rgba(239,68,68,0.15);
    color: #fecaca;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
}

/* Entry animation */
@keyframes fadeSlide {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.top-attacker-item {
    animation: fadeSlide 0.4s ease forwards;
}


        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Inter', -apple-system, sans-serif; 
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%); 
            color: #e4e7eb; 
            min-height: 100vh; 
        }
        .container { max-width: 1920px; margin: 0 auto; padding: 20px; }
        
        .loading-overlay { 
            position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
            background: rgba(10, 14, 39, 0.98); 
            display: flex; justify-content: center; align-items: center; 
            z-index: 9999; flex-direction: column; gap: 30px; 
        }
        .loading-overlay.hidden { display: none; }
        .spinner { 
            width: 80px; height: 80px; 
            border: 8px solid rgba(96, 165, 250, 0.1); 
            border-top: 8px solid #60a5fa; 
            border-radius: 50%; 
            animation: spin 1s linear infinite; 
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .loading-text { color: #60a5fa; font-size: 1.5em; font-weight: 600; }
        
        .tabs { 
            display: flex; gap: 10px; margin-bottom: 30px; 
            background: rgba(30, 41, 59, 0.5); padding: 10px; border-radius: 15px; 
        }
        .tab { 
            padding: 15px 30px; background: transparent; 
            border: 2px solid transparent; border-radius: 12px; 
            color: #94a3b8; font-weight: 600; cursor: pointer; 
            transition: all 0.3s; display: flex; align-items: center; gap: 10px; 
        }
        .tab:hover { 
            background: rgba(96, 165, 250, 0.1); 
            border-color: rgba(96, 165, 250, 0.3); 
        }
        .tab.active { 
            background: linear-gradient(135deg, #3b82f6, #2563eb); 
            color: white; border-color: #3b82f6; 
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .header { 
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%); 
            padding: 30px 40px; border-radius: 20px; margin-bottom: 30px; 
            display: flex; justify-content: space-between; align-items: center; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.5); 
        }
        .header h1 { 
            font-size: 2.2em; 
            background: linear-gradient(135deg, #60a5fa, #a78bfa, #ec4899); 
            -webkit-background-clip: text; 
            -webkit-text-fill-color: transparent; 
            font-weight: 800; 
        }
        .header-subtitle { color: #94a3b8; margin-top: 10px; font-size: 1em; }
        .badge { 
            display: inline-block; padding: 6px 14px; border-radius: 15px; 
            font-size: 0.75em; font-weight: 700; margin-left: 10px; 
        }
        .badge-ml { background: linear-gradient(135deg, #a78bfa, #ec4899); }
        .badge-pro { background: linear-gradient(135deg, #60a5fa, #3b82f6); }
        
        .status-pill { 
            display: flex; align-items: center; gap: 12px; 
            background: rgba(34, 197, 94, 0.15); 
            padding: 15px 25px; border-radius: 25px; 
            border: 2px solid #22c55e; 
            box-shadow: 0 0 20px rgba(34, 197, 94, 0.3); 
        }
        .status-pill.initializing { 
            background: rgba(251, 191, 36, 0.15); 
            border-color: #fbbf24; 
            box-shadow: 0 0 20px rgba(251, 191, 36, 0.3); 
        }
        .status-dot { 
            width: 12px; height: 12px; border-radius: 50%; 
            background: #22c55e; animation: pulse 2s infinite; 
        }
        .status-dot.initializing { background: #fbbf24; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        
        .btn-export { 
            background: linear-gradient(135deg, #3b82f6, #2563eb); 
            color: white; border: none; padding: 12px 24px; 
            border-radius: 12px; font-weight: 600; cursor: pointer; 
            transition: all 0.3s; 
        }
        .btn-export:hover { 
            transform: translateY(-2px); 
            box-shadow: 0 10px 25px rgba(59, 130, 246, 0.4); 
        }
        
        .control-section { 
            background: rgba(30, 41, 59, 0.8); 
            padding: 30px; border-radius: 20px; 
            border: 1px solid rgba(96, 165, 250, 0.2); 
            margin-bottom: 30px; 
        }
        .control-header { 
            display: flex; align-items: center; gap: 15px; 
            margin-bottom: 25px; padding-bottom: 15px; 
            border-bottom: 2px solid rgba(96, 165, 250, 0.2); 
        }
        .control-header i { font-size: 2em; color: #60a5fa; }
        .control-header h2 { font-size: 1.8em; font-weight: 700; }
        
        .model-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; margin-top: 20px; 
        }
        .model-option { 
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.9)); 
            padding: 25px; border-radius: 15px; 
            border: 2px solid rgba(96, 165, 250, 0.3); 
            cursor: pointer; transition: all 0.3s; position: relative; 
        }
        .model-option:hover { 
            transform: translateY(-5px); 
            border-color: rgba(96, 165, 250, 0.6); 
            box-shadow: 0 10px 30px rgba(96, 165, 250, 0.3); 
        }
        .model-option.active { 
            border-color: #22c55e; 
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.2), rgba(30, 41, 59, 0.9)); 
        }
        .model-option.active::before { 
            content: '✓'; position: absolute; top: 10px; right: 10px; 
            width: 30px; height: 30px; background: #22c55e; 
            border-radius: 50%; display: flex; 
            align-items: center; justify-content: center; 
            font-weight: bold; 
        }
        .model-name { 
            font-size: 1.3em; font-weight: 700; 
            margin-bottom: 10px; color: #60a5fa; 
        }
        .model-desc { color: #94a3b8; font-size: 0.9em; line-height: 1.6; }
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; margin-bottom: 30px; 
        }
        .stat-card { 
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.9) 100%); 
            padding: 25px; border-radius: 18px; 
            border: 1px solid rgba(96, 165, 250, 0.2); 
            transition: all 0.3s; position: relative; overflow: hidden; 
        }
        .stat-card::before { 
            content: ''; position: absolute; top: 0; left: 0; 
            width: 100%; height: 4px; 
            background: linear-gradient(90deg, #60a5fa, #a78bfa, #ec4899); 
        }
        .stat-card:hover { 
            transform: translateY(-5px); 
            box-shadow: 0 15px 35px rgba(0,0,0,0.5); 
            border-color: rgba(96, 165, 250, 0.5); 
        }
        .stat-icon { 
            width: 60px; height: 60px; border-radius: 15px; 
            display: flex; align-items: center; justify-content: center; 
            font-size: 1.8em; margin-bottom: 15px; 
            background: linear-gradient(135deg, rgba(96, 165, 250, 0.2), rgba(167, 139, 250, 0.2)); 
        }
        .stat-label { 
            color: #94a3b8; font-size: 0.9em; 
            text-transform: uppercase; letter-spacing: 1px; 
            margin-bottom: 10px; font-weight: 600; 
        }
        .stat-value { 
            font-size: 2.8em; font-weight: 800; 
            background: linear-gradient(135deg, #60a5fa, #a78bfa); 
            -webkit-background-clip: text; 
            -webkit-text-fill-color: transparent; 
            line-height: 1; margin-bottom: 10px; 
        }
        .stat-subtitle { color: #64748b; font-size: 0.85em; }
        
        .model-card { 
            background: linear-gradient(135deg, rgba(167, 139, 250, 0.15) 0%, rgba(236, 72, 153, 0.15) 100%); 
            padding: 30px; border-radius: 20px; 
            border: 2px solid rgba(167, 139, 250, 0.4); 
            margin-bottom: 30px; 
            box-shadow: 0 10px 30px rgba(167, 139, 250, 0.2); 
        }
        .model-header { display: flex; align-items: center; gap: 15px; margin-bottom: 25px; }
        .model-header i { font-size: 2.5em; color: #a78bfa; }
        .model-header h2 { font-size: 1.6em; font-weight: 700; }
        .model-metrics { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); 
            gap: 20px; 
        }
        .model-metric { 
            background: rgba(15, 23, 42, 0.6); 
            padding: 20px; border-radius: 15px; 
            border: 1px solid rgba(167, 139, 250, 0.3); 
            transition: all 0.3s; 
        }
        .model-metric:hover { 
            border-color: rgba(167, 139, 250, 0.6); 
            transform: translateY(-3px); 
        }
        .model-metric-label { 
            color: #a78bfa; font-size: 0.8em; 
            text-transform: uppercase; margin-bottom: 10px; 
        }
        .model-metric-value { font-size: 1.8em; font-weight: 700; color: #e4e7eb; }
        
        ::-webkit-scrollbar { width: 12px; }
        ::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.5); }
        ::-webkit-scrollbar-thumb { 
            background: rgba(96, 165, 250, 0.5); 
            border-radius: 6px; 
        }
        ::-webkit-scrollbar-thumb:hover { background: rgba(96, 165, 250, 0.7); }
        
        @media (max-width: 768px) { 
            .header { flex-direction: column; gap: 20px; } 
            .stats-grid { grid-template-columns: 1fr; } 
        }

        .btn-logout {
    background: linear-gradient(135deg, #64748b, #334155); /* subtle gray-blue */
    color: white;
    border: none;
    padding: 12px 24px;
    border-radius: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s;
}

.btn-logout:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 25px rgba(100, 116, 139, 0.4);
}
    </style>
</head>
<script src="/static/dashboard.js"></script>
<body>
    <div class="loading-overlay" id="loadingOverlay">
        <div class="spinner"></div>
        <div class="loading-text"><i class="fas fa-brain"></i> Initializing Advanced IDS Platform</div>
        <div style="color: #94a3b8; margin-top: 10px;">Loading ML models and connecting to honeypot...</div>
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
            <div style="display: flex; gap: 12px; align-items: center;">
    
                <div class="status-pill initializing" id="statusPill">
                    <div class="status-dot initializing" id="statusDot"></div>
                    <div>
                        <div style="font-weight: 600; font-size: 1.1em;" id="statusText">Initializing</div>
                        <div style="font-size: 0.85em; color: #94a3b8;">
                            Model: <span id="current-model-display">Loading...</span>
                        </div>
                    </div>
                </div>

                <button class="btn-export" onclick="exportData()">
                    <i class="fas fa-download"></i> Export Report
                </button>

                <button class="btn-logout" onclick="logout()">
                    <i class="fas fa-right-from-bracket"></i> Logout
                </button>

            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('dashboard', this)">
                <i class="fas fa-chart-line"></i> Dashboard
            </div>
            <div class="tab" onclick="switchTab('control', this)">
                <i class="fas fa-sliders"></i> Control Center
            </div>
        </div>
        <!-- Dashboard Tab Content -->
        <div id="dashboard-tab" class="tab-content active">
            <div class="model-card">
                <div class="model-header">
                    <i class="fas fa-brain"></i>
                    <div>
                        <h2>Machine Learning Engine</h2>
                        <div style="color: #94a3b8; font-size: 0.95em; margin-top: 5px;">Powered by trained NSL-KDD/UNSW-NB15 detection models</div>
                    </div>
                </div>
                <div class="model-metrics">
                    <div class="model-metric">
                        <div class="model-metric-label">Algorithm</div>
                        <div class="model-metric-value" id="model-name">Loading...</div>
                    </div>
                    <div class="model-metric">
                        <div class="model-metric-label">Accuracy</div>
                        <div class="model-metric-value" id="model-accuracy">--%</div>
                    </div>
                    <div class="model-metric">
                        <div class="model-metric-label">F1-Score</div>
                        <div class="model-metric-value" id="model-f1">--%</div>
                    </div>
                    <div class="model-metric">
                        <div class="model-metric-label">Avg Confidence</div>
                        <div class="model-metric-value" id="avg-confidence">--%</div>
                    </div>
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-chart-line"></i></div>
                    <div class="stat-label">Total Events</div>
                    <div class="stat-value" id="total-events">0</div>
                    <div class="stat-subtitle" id="events-per-min">0 events/min</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-exclamation-triangle"></i></div>
                    <div class="stat-label">Attacks Detected</div>
                    <div class="stat-value" id="attacks-detected">0</div>
                    <div class="stat-subtitle" id="attack-rate">0% attack rate</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-network-wired"></i></div>
                    <div class="stat-label">Unique Attackers</div>
                    <div class="stat-value" id="unique-attackers">0</div>
                    <div class="stat-subtitle">distinct source IPs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-robot"></i></div>
                    <div class="stat-label">ML Predictions</div>
                    <div class="stat-value" id="ml-predictions">0</div>
                    <div class="stat-subtitle" id="ml-prediction-rate">0 normal</div>
                </div>
            </div>
            
            <div class="charts-grid" style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 25px; margin-bottom: 30px;">
                <div class="chart-card" style="background: rgba(30, 41, 59, 0.8); padding: 30px; border-radius: 20px; border: 1px solid rgba(96, 165, 250, 0.2); box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
                    <div class="chart-header" style="display: flex; align-items: center; gap: 12px; margin-bottom: 25px;">
                        <i class="fas fa-chart-area" style="color: #60a5fa; font-size: 1.4em;"></i>
                        <h3 style="font-size: 1.3em; font-weight: 700;">Attack Timeline (24h)</h3>
                    </div>
                    <canvas id="timelineChart" style="max-height: 350px;"></canvas>
                </div>
                <div class="chart-card" style="background: rgba(30, 41, 59, 0.8); padding: 30px; border-radius: 20px; border: 1px solid rgba(96, 165, 250, 0.2); box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
                    <div class="chart-header" style="display: flex; align-items: center; gap: 12px; margin-bottom: 25px;">
                        <i class="fas fa-chart-pie" style="color: #60a5fa; font-size: 1.4em;"></i>
                        <h3 style="font-size: 1.3em; font-weight: 700;">Attack Types</h3>
                    </div>
                    <canvas id="attackTypesChart" style="max-height: 350px;"></canvas>
                </div>
                <div class="chart-card" style="background: rgba(30, 41, 59, 0.8); padding: 30px; border-radius: 20px; border: 1px solid rgba(96, 165, 250, 0.2); box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
                    <div class="chart-header" style="display: flex; align-items: center; gap: 12px; margin-bottom: 25px;">
                        <i class="fas fa-chart-bar" style="color: #60a5fa; font-size: 1.4em;"></i>
                        <h3 style="font-size: 1.3em; font-weight: 700;">Severity Distribution</h3>
                    </div>
                    <canvas id="severityChart" style="max-height: 350px;"></canvas>
                </div>
                <div class="chart-card" style="background: rgba(30, 41, 59, 0.8); padding: 30px; border-radius: 20px; border: 1px solid rgba(96, 165, 250, 0.2); box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
                    <div class="chart-header" style="display: flex; align-items: center; gap: 12px; margin-bottom: 25px;">
                        <i class="fas fa-percentage" style="color: #60a5fa; font-size: 1.4em;"></i>
                        <h3 style="font-size: 1.3em; font-weight: 700;">ML Confidence Scores</h3>
                    </div>
                    <canvas id="confidenceChart" style="max-height: 350px;"></canvas>
                </div>
                <div class="chart-card" style="background: rgba(30, 41, 59, 0.8); padding: 30px; border-radius: 20px; border: 1px solid rgba(96, 165, 250, 0.2); box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
                    <div class="chart-header" style="display: flex; align-items: center; gap: 12px; margin-bottom: 25px;">
                        <i class="fas fa-globe" style="color: #60a5fa; font-size: 1.4em;"></i>
                        <h3 style="font-size: 1.3em; font-weight: 700;">Geographic Distribution</h3>
                    </div>
                    <canvas id="geoChart" style="max-height: 350px;"></canvas>
                </div>
            </div>
            
            <div class="incidents-card" style="background: rgba(30, 41, 59, 0.8); padding: 30px; border-radius: 20px; border: 1px solid rgba(96, 165, 250, 0.2);">
                <div class="chart-header" style="display: flex; align-items: center; gap: 12px; margin-bottom: 25px;">
                    <i class="fas fa-bell" style="color: #60a5fa; font-size: 1.4em;"></i>
                    <h3 style="font-size: 1.3em; font-weight: 700;">Live Incident Feed</h3>
                </div>
                <div id="incident-list" style="max-height: 600px; overflow-y: auto;">
                    <div style="text-align: center; padding: 40px; color: #94a3b8;">
                        <i class="fas fa-spinner fa-spin"></i> Waiting for IDS initialization...
                    </div>
                </div>
            </div>
        </div>
        <!-- Enhanced Control Center Tab -->
        <div id="control-tab" class="tab-content">
            <!-- Model Selection -->
            <div class="control-section">
                <div class="control-header">
                    <i class="fas fa-brain"></i>
                    <div>
                        <h2>ML Model Selection</h2>
                        <div style="color: #94a3b8; font-size: 0.95em; margin-top: 5px;">Switch between different machine learning models in real-time</div>
                    </div>
                </div>
                <div class="model-grid" id="model-selection">
                    <div class="model-option" onclick="selectModel('Random Forest')">
                        <div class="model-name">🌲 Random Forest</div>
                        <div class="model-desc">Ensemble tree-based classifier with high accuracy</div>
                    </div>
                    <div class="model-option" onclick="selectModel('XGBoost')">
                        <div class="model-name">⚡ XGBoost</div>
                        <div class="model-desc">Gradient boosting with excellent performance</div>
                    </div>
                    <div class="model-option" onclick="selectModel('Decision Tree')">
                        <div class="model-name">🌳 Decision Tree</div>
                        <div class="model-desc">Simple rule-based tree classifier</div>
                    </div>
                    <div class="model-option" onclick="selectModel('KNN')">
                        <div class="model-name">📍 K-Nearest Neighbors</div>
                        <div class="model-desc">Distance-based classifier</div>
                    </div>
                    <div class="model-option" onclick="selectModel('Logistic Regression')">
                        <div class="model-name">📈 Logistic Regression</div>
                        <div class="model-desc">Linear probabilistic classifier</div>
                    </div>
                    <div class="model-option" onclick="selectModel('LightGBM')">
                        <div class="model-name">💡 LightGBM</div>
                        <div class="model-desc">Fast gradient boosting framework</div>
                    </div>
                </div>
            </div>

            <!-- Model Performance Comparison -->
            <div class="control-section">
                <div class="control-header">
                    <i class="fas fa-chart-bar"></i>
                    <div>
                        <h2>Model Performance Comparison</h2>
                        <div style="color: #94a3b8; font-size: 0.95em; margin-top: 5px;">Real-time comparison of different ML models</div>
                    </div>
                </div>
                <div id="model-performance-list" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                    <div style="text-align: center; padding: 40px; color: #94a3b8;">
                        <i class="fas fa-spinner fa-spin"></i> Loading model performance data...
                    </div>
                </div>
            </div>

            <!-- Attack Simulation -->
            <div class="control-section">
                <div class="control-header">
                    <i class="fas fa-bomb"></i>
                    <div>
                        <h2>Attack Simulation</h2>
                        <div style="color: #94a3b8; font-size: 0.95em; margin-top: 5px;">Test IDS with simulated attacks</div>
                    </div>
                </div>
                <div class="attack-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px;">
                    <div class="attack-card" style="background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.9)); padding: 25px; border-radius: 15px; border: 2px solid rgba(239, 68, 68, 0.3); transition: all 0.3s;">
                        <div class="attack-icon" style="width: 60px; height: 60px; background: linear-gradient(135deg, rgba(239, 68, 68, 0.3), rgba(220, 38, 38, 0.3)); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.8em; color: #ef4444; margin-bottom: 15px;">
                            <i class="fas fa-server"></i>
                        </div>
                        <div class="attack-name" style="font-size: 1.3em; font-weight: 700; margin-bottom: 10px;">DDoS Attack</div>
                        <div class="attack-desc" style="color: #94a3b8; font-size: 0.85em; margin-bottom: 20px; line-height: 1.6;">Simulate distributed denial-of-service attack with high packet volume</div>
                        <div class="attack-controls" style="display: flex; gap: 10px; align-items: center;">
                            <input type="number" class="attack-input" id="ddos-count" value="100" min="1" max="1000" style="flex: 1; background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(96, 165, 250, 0.3); padding: 10px 15px; border-radius: 8px; color: #e4e7eb; font-size: 0.9em;">
                            <button class="btn-simulate" onclick="simulateAttack('ddos', document.getElementById('ddos-count').value)" style="background: linear-gradient(135deg, #ef4444, #dc2626); color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.3s; white-space: nowrap;">
                                <i class="fas fa-play"></i> Simulate
                            </button>
                        </div>
                    </div>
                    
                    <div class="attack-card" style="background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.9)); padding: 25px; border-radius: 15px; border: 2px solid rgba(239, 68, 68, 0.3);">
                        <div class="attack-icon" style="width: 60px; height: 60px; background: linear-gradient(135deg, rgba(239, 68, 68, 0.3), rgba(220, 38, 38, 0.3)); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.8em; color: #ef4444; margin-bottom: 15px;">
                            <i class="fas fa-database"></i>
                        </div>
                        <div class="attack-name" style="font-size: 1.3em; font-weight: 700; margin-bottom: 10px;">SQL Injection</div>
                        <div class="attack-desc" style="color: #94a3b8; font-size: 0.85em; margin-bottom: 20px; line-height: 1.6;">Simulate SQL injection attempts with malicious payloads</div>
                        <div class="attack-controls" style="display: flex; gap: 10px; align-items: center;">
                            <input type="number" class="attack-input" id="sql-count" value="10" min="1" max="100" style="flex: 1; background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(96, 165, 250, 0.3); padding: 10px 15px; border-radius: 8px; color: #e4e7eb; font-size: 0.9em;">
                            <button class="btn-simulate" onclick="simulateAttack('sql_injection', document.getElementById('sql-count').value)" style="background: linear-gradient(135deg, #ef4444, #dc2626); color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer;">
                                <i class="fas fa-play"></i> Simulate
                            </button>
                        </div>
                    </div>
                    
                    <div class="attack-card" style="background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.9)); padding: 25px; border-radius: 15px; border: 2px solid rgba(239, 68, 68, 0.3);">
                        <div class="attack-icon" style="width: 60px; height: 60px; background: linear-gradient(135deg, rgba(239, 68, 68, 0.3), rgba(220, 38, 38, 0.3)); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.8em; color: #ef4444; margin-bottom: 15px;">
                            <i class="fas fa-key"></i>
                        </div>
                        <div class="attack-name" style="font-size: 1.3em; font-weight: 700; margin-bottom: 10px;">Brute Force</div>
                        <div class="attack-desc" style="color: #94a3b8; font-size: 0.85em; margin-bottom: 20px; line-height: 1.6;">Simulate password brute-force attack on SSH service</div>
                        <div class="attack-controls" style="display: flex; gap: 10px; align-items: center;">
                            <input type="number" class="attack-input" id="brute-count" value="50" min="1" max="200" style="flex: 1; background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(96, 165, 250, 0.3); padding: 10px 15px; border-radius: 8px; color: #e4e7eb; font-size: 0.9em;">
                            <button class="btn-simulate" onclick="simulateAttack('brute_force', document.getElementById('brute-count').value)" style="background: linear-gradient(135deg, #ef4444, #dc2626); color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer;">
                                <i class="fas fa-play"></i> Simulate
                            </button>
                        </div>
                    </div>
                    
                    <div class="attack-card" style="background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.9)); padding: 25px; border-radius: 15px; border: 2px solid rgba(239, 68, 68, 0.3);">
                        <div class="attack-icon" style="width: 60px; height: 60px; background: linear-gradient(135deg, rgba(239, 68, 68, 0.3), rgba(220, 38, 38, 0.3)); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.8em; color: #ef4444; margin-bottom: 15px;">
                            <i class="fas fa-terminal"></i>
                        </div>
                        <div class="attack-name" style="font-size: 1.3em; font-weight: 700; margin-bottom: 10px;">Command Injection</div>
                        <div class="attack-desc" style="color: #94a3b8; font-size: 0.85em; margin-bottom: 20px; line-height: 1.6;">Simulate OS command injection attempts</div>
                        <div class="attack-controls" style="display: flex; gap: 10px; align-items: center;">
                            <input type="number" class="attack-input" id="cmd-count" value="15" min="1" max="100" style="flex: 1; background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(96, 165, 250, 0.3); padding: 10px 15px; border-radius: 8px; color: #e4e7eb; font-size: 0.9em;">
                            <button class="btn-simulate" onclick="simulateAttack('command_injection', document.getElementById('cmd-count').value)" style="background: linear-gradient(135deg, #ef4444, #dc2626); color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer;">
                                <i class="fas fa-play"></i> Simulate
                            </button>
                        </div>
                    </div>
                    
                    <div class="attack-card" style="background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.9)); padding: 25px; border-radius: 15px; border: 2px solid rgba(239, 68, 68, 0.3);">
                        <div class="attack-icon" style="width: 60px; height: 60px; background: linear-gradient(135deg, rgba(239, 68, 68, 0.3), rgba(220, 38, 38, 0.3)); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.8em; color: #ef4444; margin-bottom: 15px;">
                            <i class="fas fa-virus"></i>
                        </div>
                        <div class="attack-name" style="font-size: 1.3em; font-weight: 700; margin-bottom: 10px;">Malware Intrusion</div>
                        <div class="attack-desc" style="color: #94a3b8; font-size: 0.85em; margin-bottom: 20px; line-height: 1.6;">Simulate malware intrusion attempts</div>
                        <div class="attack-controls" style="display: flex; gap: 10px; align-items: center;">
                            <input type="number" class="attack-input" id="malware-count" value="20" min="1" max="100" style="flex: 1; background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(96, 165, 250, 0.3); padding: 10px 15px; border-radius: 8px; color: #e4e7eb; font-size: 0.9em;">
                            <button class="btn-simulate" onclick="simulateAttack('malware_intrusion', document.getElementById('malware-count').value)" style="background: linear-gradient(135deg, #ef4444, #dc2626); color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer;">
                                <i class="fas fa-play"></i> Simulate
                            </button>
                        </div>
                    </div>
                    
                    <div class="attack-card" style="background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.9)); padding: 25px; border-radius: 15px; border: 2px solid rgba(239, 68, 68, 0.3);">
                        <div class="attack-icon" style="width: 60px; height: 60px; background: linear-gradient(135deg, rgba(239, 68, 68, 0.3), rgba(220, 38, 38, 0.3)); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.8em; color: #ef4444; margin-bottom: 15px;">
                            <i class="fas fa-bug"></i>
                        </div>
                        <div class="attack-name" style="font-size: 1.3em; font-weight: 700; margin-bottom: 10px;">Zero-Day Exploit</div>
                        <div class="attack-desc" style="color: #94a3b8; font-size: 0.85em; margin-bottom: 20px; line-height: 1.6;">Simulate unknown vulnerability exploitation</div>
                        <div class="attack-controls" style="display: flex; gap: 10px; align-items: center;">
                            <input type="number" class="attack-input" id="zeroday-count" value="5" min="1" max="50" style="flex: 1; background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(96, 165, 250, 0.3); padding: 10px 15px; border-radius: 8px; color: #e4e7eb; font-size: 0.9em;">
                            <button class="btn-simulate" onclick="simulateAttack('zero_day', document.getElementById('zeroday-count').value)" style="background: linear-gradient(135deg, #ef4444, #dc2626); color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer;">
                                <i class="fas fa-play"></i> Simulate
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="simulation-log" id="simulation-log" style="background: rgba(15, 23, 42, 0.9); padding: 20px; border-radius: 12px; border: 1px solid rgba(96, 165, 250, 0.2); max-height: 300px; overflow-y: auto; font-family: 'Courier New', monospace; font-size: 0.85em; margin-top: 20px;">
                    <div style="color: #64748b;">Simulation log ready...</div>
                </div>
            </div>

            <!-- IP Blacklist -->
            <div class="control-section">
                <div class="control-header">
                    <i class="fas fa-ban"></i>
                    <div>
                        <h2>IP Blacklist Management</h2>
                        <div style="color: #94a3b8; font-size: 0.95em; margin-top: 5px;">Manage blacklisted IP addresses</div>
                    </div>
                </div>
                <div style="display: flex; gap: 10px; margin-bottom: 20px;">
                    <input type="text" id="blacklist-ip-input" placeholder="Enter IP address (e.g., 192.168.1.100)" style="flex: 1; background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(96, 165, 250, 0.3); padding: 12px 20px; border-radius: 10px; color: #e4e7eb; font-size: 1em;">
                    <button onclick="addToBlacklist()" style="background: linear-gradient(135deg, #ef4444, #dc2626); color: white; border: none; padding: 12px 30px; border-radius: 10px; font-weight: 600; cursor: pointer; white-space: nowrap;">
                        <i class="fas fa-plus"></i> Add to Blacklist
                    </button>
                </div>
                <div id="blacklist-container" style="max-height: 400px; overflow-y: auto;">
                    <div style="text-align: center; padding: 40px; color: #94a3b8;">
                        <i class="fas fa-shield-alt"></i> No blacklisted IPs yet
                    </div>
                </div>
            </div>

            <!-- Top Attackers -->
            <div class="control-section">
                <div class="control-header">
                    <i class="fas fa-user-secret"></i>
                    <div>
                        <h2>Top Attackers</h2>
                        <div style="color: #94a3b8; font-size: 0.95em; margin-top: 5px;">Most active attacking IP addresses</div>
                    </div>
                </div>
                <div id="top-attackers-list">
                    <div style="text-align: center; padding: 40px; color: #94a3b8;">
                        <i class="fas fa-spinner fa-spin"></i> Loading attacker data...
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>

"""