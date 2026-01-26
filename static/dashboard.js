// Advanced IDS Dashboard - Complete JavaScript with Fixed Model Switching

const socket = io();
let charts = {};
let currentActiveModel = null;

// ✅ FIX: Track model changes globally
socket.on('model_switched', function(data) {
    console.log('Model switched:', data);
    currentActiveModel = data.model;
    
    // Update all model displays immediately
    updateModelDisplay(data.model);
    
    // Show notification
    showNotification(`Switched to ${data.model}`, 'success');
    
    // Force refresh all data
    loadStats();
    loadCharts();
});

// ✅ FIX: Update all model name displays
function updateModelDisplay(modelName) {
    const displays = [
        'model-name',
        'current-model-display'
    ];
    
    displays.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = modelName;
        }
    });
    
    // Update active model in UI
    updateActiveModelUI(modelName);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard loading...');
    initializeCharts();
    loadStats();
    loadCharts();
    loadIncidents();
    loadBlacklist();
    loadTopAttackers();
    loadModelPerformance();
    
    // Polling for updates
    setInterval(loadStats, 5000);
    setInterval(loadCharts, 15000);
    setInterval(loadIncidents, 10000);
    setInterval(loadTopAttackers, 30000);
    setInterval(loadModelPerformance, 20000);
});

// Socket event handlers
socket.on('connect', function() {
    console.log('Connected to server');
});

socket.on('initialization_complete', function(data) {
    console.log('IDS initialized:', data);
    document.getElementById('loadingOverlay').classList.add('hidden');
    document.getElementById('statusPill').classList.remove('initializing');
    document.getElementById('statusDot').classList.remove('initializing');
    document.getElementById('statusText').textContent = 'Active';
    
    currentActiveModel = data.model;
    updateModelDisplay(data.model);
});

socket.on('stats_update', function(stats) {
    updateStats(stats);
});

socket.on('new_incident', function(incident) {
    addIncident(incident);
});

socket.on('simulation_started', function(data) {
    addSimulationLog(`Started ${data.attack_type} simulation with ${data.count} attacks`, 'success');
});

socket.on('blacklist_updated', function(data) {
    loadBlacklist();
    showNotification(`IP ${data.ip} ${data.action} blacklist`, 'info');
});

// Tab switching
function switchTab(tabName) {
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    event.target.closest('.tab').classList.add('active');
    document.getElementById(tabName + '-tab').classList.add('active');
    
    if (tabName === 'control') {
        loadModelPerformance();
        loadTopAttackers();
    }
}

// ✅ FIXED: Model selection with proper UI update
async function selectModel(modelName) {
    console.log('Selecting model:', modelName);
    
    try {
        const response = await fetch('/api/models/switch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({model_name: modelName})
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentActiveModel = modelName;
            updateModelDisplay(modelName);
            updateActiveModelUI(modelName);
            showNotification(`Switched to ${modelName}`, 'success');
        } else {
            showNotification(`Failed to switch model: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Model switch error:', error);
        showNotification('Failed to switch model', 'error');
    }
}

// ✅ FIX: Update active model UI
function updateActiveModelUI(modelName) {
    document.querySelectorAll('.model-option').forEach(option => {
        option.classList.remove('active');
        const optionModelName = option.querySelector('.model-name').textContent.trim().substring(2).trim();
        if (optionModelName === modelName) {
            option.classList.add('active');
        }
    });
}

// Load and update stats
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        updateStats(stats);
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// function updateStats(stats) {
//     // ✅ FIX: Always use the current model name
//     const modelName = stats.model_name || currentActiveModel || 'Loading...';
    
//     document.getElementById('total-events').textContent = stats.total_events || 0;
//     document.getElementById('attacks-detected').textContent = stats.attacks_detected || 0;
//     document.getElementById('unique-attackers').textContent = stats.unique_attackers || 0;
//     document.getElementById('ml-predictions').textContent = stats.total_events || 0;
    
//     document.getElementById('events-per-min').textContent = `${stats.events_per_minute || 0} events/min`;
//     document.getElementById('attack-rate').textContent = `${stats.attack_rate || 0}% attack rate`;
//     document.getElementById('ml-prediction-rate').textContent = `${stats.model_predictions?.normal || 0} normal`;
    
//     // ✅ FIX: Update all model name displays
//     updateModelDisplay(modelName);
    
//     document.getElementById('model-accuracy').textContent = `${stats.model_accuracy || 0}%`;
//     document.getElementById('model-f1').textContent = `${stats.model_f1 || 0}%`;
//     document.getElementById('avg-confidence').textContent = `${stats.avg_confidence || 0}%`;
// }

function updateStats(stats) {

    // ✅ CRITICAL FIX — hide loader when backend is ready
    if (stats.initialized === true) {
        document.getElementById('loadingOverlay').classList.add('hidden');

        document.getElementById('statusPill').classList.remove('initializing');
        document.getElementById('statusDot').classList.remove('initializing');
        document.getElementById('statusText').textContent = 'Active';
    }

    const modelName = stats.model_name || currentActiveModel || 'Loading...';

    document.getElementById('total-events').textContent = stats.total_events || 0;
    document.getElementById('attacks-detected').textContent = stats.attacks_detected || 0;
    document.getElementById('unique-attackers').textContent = stats.unique_attackers || 0;
    document.getElementById('ml-predictions').textContent = stats.total_events || 0;

    document.getElementById('events-per-min').textContent =
        `${stats.events_per_minute || 0} events/min`;

    document.getElementById('attack-rate').textContent =
        `${stats.attack_rate || 0}% attack rate`;

    document.getElementById('ml-prediction-rate').textContent =
        `${stats.model_predictions?.normal || 0} normal`;

    updateModelDisplay(modelName);

    document.getElementById('model-accuracy').textContent =
        `${stats.model_accuracy || 0}%`;

    document.getElementById('model-f1').textContent =
        `${stats.model_f1 || 0}%`;

    document.getElementById('avg-confidence').textContent =
        `${stats.avg_confidence || 0}%`;
}

// Chart initialization
function initializeCharts() {
    const chartConfig = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {color: '#e4e7eb'}
            }
        },
        scales: {
            x: {ticks: {color: '#94a3b8'}, grid: {color: 'rgba(96, 165, 250, 0.1)'}},
            y: {ticks: {color: '#94a3b8'}, grid: {color: 'rgba(96, 165, 250, 0.1)'}}
        }
    };
    
    charts.timeline = new Chart(document.getElementById('timelineChart'), {
        type: 'line',
        data: {labels: [], datasets: [{label: 'Attacks', data: [], borderColor: '#60a5fa', backgroundColor: 'rgba(96, 165, 250, 0.1)', fill: true}]},
        options: chartConfig
    });
    
    charts.attackTypes = new Chart(document.getElementById('attackTypesChart'), {
        type: 'doughnut',
        data: {labels: [], datasets: [{data: [], backgroundColor: ['#ef4444', '#f59e0b', '#eab308', '#22c55e', '#3b82f6', '#a78bfa', '#ec4899']}]},
        options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {labels: {color: '#e4e7eb'}}}}
    });
    
    charts.severity = new Chart(document.getElementById('severityChart'), {
        type: 'bar',
        data: {labels: [], datasets: [{label: 'Count', data: [], backgroundColor: ['#dc2626', '#f59e0b', '#eab308', '#3b82f6']}]},
        options: chartConfig
    });
    
    charts.confidence = new Chart(document.getElementById('confidenceChart'), {
        type: 'bar',
        data: {labels: [], datasets: [{label: 'Incidents', data: [], backgroundColor: '#60a5fa'}]},
        options: chartConfig
    });
    
    charts.geo = new Chart(document.getElementById('geoChart'), {
        type: 'bar',
        data: {labels: [], datasets: [{label: 'Attacks', data: [], backgroundColor: '#a78bfa'}]},
        options: {responsive: true, maintainAspectRatio: false, indexAxis: 'y', scales: {x: {ticks: {color: '#94a3b8'}, grid: {color: 'rgba(96, 165, 250, 0.1)'}}, y: {ticks: {color: '#94a3b8'}, grid: {color: 'rgba(96, 165, 250, 0.1)'}}}}
    });
}

async function loadCharts() {
    try {
        // Timeline
        const timelineData = await fetch('/api/attack_timeline').then(r => r.json());
        charts.timeline.data.labels = timelineData.map(d => d.time);
        charts.timeline.data.datasets[0].data = timelineData.map(d => d.count);
        charts.timeline.update();
        
        // Attack types
        const attackTypes = await fetch('/api/attack_types_distribution').then(r => r.json());
        charts.attackTypes.data.labels = attackTypes.map(d => d.type);
        charts.attackTypes.data.datasets[0].data = attackTypes.map(d => d.count);
        charts.attackTypes.update();
        
        // Severity
        const severity = await fetch('/api/severity_distribution').then(r => r.json());
        charts.severity.data.labels = severity.map(d => d.severity);
        charts.severity.data.datasets[0].data = severity.map(d => d.count);
        charts.severity.update();
        
        // Confidence
        const confidence = await fetch('/api/confidence_distribution').then(r => r.json());
        charts.confidence.data.labels = confidence.map(d => d.range);
        charts.confidence.data.datasets[0].data = confidence.map(d => d.count);
        charts.confidence.update();
        
        // Geo
        const geo = await fetch('/api/geo_distribution').then(r => r.json());
        charts.geo.data.labels = geo.slice(0, 10).map(d => d.country);
        charts.geo.data.datasets[0].data = geo.slice(0, 10).map(d => d.count);
        charts.geo.update();
    } catch (error) {
        console.error('Error loading charts:', error);
    }
}

// Incident management
async function loadIncidents() {
    try {
        const incidents = await fetch('/api/incidents?limit=50').then(r => r.json());
        const container = document.getElementById('incident-list');
        
        if (incidents.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #94a3b8;"><i class="fas fa-shield-alt"></i> No incidents detected yet</div>';
            return;
        }
        
        container.innerHTML = incidents.map(inc => createIncidentHTML(inc)).join('');
    } catch (error) {
        console.error('Error loading incidents:', error);
    }
}

function addIncident(incident) {
    const container = document.getElementById('incident-list');
    const existingPlaceholder = container.querySelector('div[style*="text-align: center"]');
    if (existingPlaceholder) {
        container.innerHTML = '';
    }
    
    container.insertAdjacentHTML('afterbegin', createIncidentHTML(incident));
    
    const incidents = container.querySelectorAll('.incident-item');
    if (incidents.length > 50) {
        incidents[incidents.length - 1].remove();
    }
}

// function createIncidentHTML(inc) {
//     const severityClass = inc.severity?.toLowerCase() || 'low';
//     const timestamp = new Date(inc.timestamp).toLocaleString();
//     const modelName = inc.model_name || currentActiveModel || 'Unknown';
    
//     return `
//         <div class="incident-item ${severityClass}">
//             <div class="incident-header">
//                 <div class="incident-type">${inc.attack_type || 'Unknown Attack'}</div>
//                 <div class="incident-badges">
//                     <span class="incident-badge badge-severity">${inc.severity || 'Low'}</span>
//                     <span class="incident-badge badge-confidence">${Math.round((inc.confidence || 0) * 100)}%</span>
//                     <span class="incident-badge badge-model">${modelName}</span>
//                     ${inc.is_blacklisted ? '<span class="incident-badge badge-blacklisted">BLACKLISTED</span>' : ''}
//                 </div>
//             </div>
//             <div class="incident-details">
//                 <strong>Source:</strong> <code>${inc.src_ip || 'Unknown'}</code> 
//                 ${inc.country ? `<span style="color: #60a5fa;">[${inc.country}]</span>` : ''}
//                 <br>
//                 <strong>Time:</strong> ${timestamp}
//                 ${inc.details ? `<br><strong>Details:</strong> ${inc.details}` : ''}
//             </div>
//         </div>
//     `;
// }

function createIncidentHTML(inc) {
    const severity = inc.severity || "Low";
    const severityColors = {
        "Critical": "#dc2626",
        "High": "#ef4444",
        "Medium": "#f59e0b",
        "Low": "#22c55e"
    };

    const color = severityColors[severity] || "#64748b";
    const timestamp = new Date(inc.timestamp).toLocaleString();
    const modelName = inc.model_name || currentActiveModel || "Unknown";

    const details = inc.details || {};
    const nsl = details.nsl_kdd_features || {};

    return `
    <div class="incident-item" style="
        background: rgba(15,23,42,0.95);
        border-left: 6px solid ${color};
        padding: 18px 22px;
        border-radius: 14px;
        margin-bottom: 14px;
        animation: slideIn 0.4s ease;
    ">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="font-size:1.1em; font-weight:700;">
                🚨 ${inc.attack_type || "Suspicious Activity"}
            </div>
            <span style="
                background:${color};
                color:white;
                padding:4px 10px;
                border-radius:20px;
                font-size:0.75em;
                font-weight:700;
            ">
                ${severity}
            </span>
        </div>

        <div style="margin-top:6px; font-size:0.9em; color:#94a3b8;">
            Confidence: <b>${Math.round((inc.confidence || 0) * 100)}%</b>
            • Model: <b>${modelName}</b>
        </div>

        <div style="margin-top:8px; font-size:0.9em;">
            🌍 <b>Source IP:</b> <code>${inc.src_ip || "Unknown"}</code>
            ${inc.country ? `<span style="color:#60a5fa;"> [${inc.country}]</span>` : ""}
        </div>

        <div style="margin-top:4px; font-size:0.85em; color:#94a3b8;">
            ⏱ ${timestamp}
        </div>

        ${details.username ? `
        <div style="margin-top:6px;">
            👤 <b>User:</b> ${details.username}
        </div>` : ""}

        ${details.command ? `
        <div style="
            margin-top:8px;
            background: rgba(239,68,68,0.12);
            padding:10px;
            border-radius:8px;
            font-family: monospace;
            color:#fda4af;
        ">
            💻 ${details.command}
        </div>` : ""}

        <details style="margin-top:10px;">
            <summary style="cursor:pointer; color:#60a5fa; font-weight:600;">
                Technical Indicators
            </summary>
            <div style="margin-top:8px; font-size:0.85em; color:#cbd5f5;">
                • Failed Logins: ${details.failed_logins || 0}<br>
                • Compromised: ${nsl.num_compromised || 0}<br>
                • Root Shell: ${nsl.root_shell || 0}<br>
                • Count: ${nsl.count || 0}
            </div>
        </details>
    </div>
    `;
}



// Attack simulation
async function simulateAttack(attackType, count) {
    try {
        addSimulationLog(`Launching ${attackType} simulation with ${count} attacks...`, 'info');
        
        const response = await fetch('/api/simulate/attack', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({attack_type: attackType, count: parseInt(count)})
        });
        
        const result = await response.json();
        
        if (result.success) {
            addSimulationLog(`✓ ${result.attack_type}: ${result.count} attacks simulated`, 'success');
        } else {
            addSimulationLog(`✗ Failed: ${result.error}`, 'error');
        }
    } catch (error) {
        addSimulationLog(`✗ Error: ${error.message}`, 'error');
    }
}

function addSimulationLog(message, type) {
    const log = document.getElementById('simulation-log');
    const timestamp = new Date().toLocaleTimeString();
    const colorClass = type === 'success' ? 'log-success' : type === 'error' ? 'log-error' : '';
    
    log.insertAdjacentHTML('afterbegin', `
        <div class="log-entry">
            <span class="log-timestamp">[${timestamp}]</span>
            <span class="${colorClass}">${message}</span>
        </div>
    `);
    
    const entries = log.querySelectorAll('.log-entry');
    if (entries.length > 50) {
        entries[entries.length - 1].remove();
    }
}

// Blacklist management
async function loadBlacklist() {
    try {
        const data = await fetch('/api/blacklist').then(r => r.json());
        const container = document.getElementById('blacklist-container');
        
        if (data.blacklist.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #94a3b8;"><i class="fas fa-shield-alt"></i> No blacklisted IPs yet</div>';
            return;
        }
        
        container.innerHTML = data.blacklist.map(ip => `
            <div class="blacklist-item">
                <span class="blacklist-ip">${ip}</span>
                <button class="btn-remove" onclick="removeFromBlacklist('${ip}')">
                    <i class="fas fa-trash"></i> Remove
                </button>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading blacklist:', error);
    }
}

async function addToBlacklist() {
    const input = document.getElementById('blacklist-ip-input');
    const ip = input.value.trim();
    
    if (!ip) return;
    
    try {
        const response = await fetch('/api/blacklist/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip})
        });
        
        const result = await response.json();
        
        if (result.success) {
            input.value = '';
            loadBlacklist();
            showNotification(`Added ${ip} to blacklist`, 'success');
        }
    } catch (error) {
        showNotification('Failed to add IP', 'error');
    }
}

async function removeFromBlacklist(ip) {
    try {
        await fetch('/api/blacklist/remove', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip})
        });
        
        loadBlacklist();
    } catch (error) {
        console.error('Error removing from blacklist:', error);
    }
}

// Top attackers
// async function loadTopAttackers() {
//     try {
//         const attackers = await fetch('/api/top/attackers').then(r => r.json());
//         const container = document.getElementById('top-attackers-list');
        
//         if (attackers.length === 0) {
//             container.innerHTML = '<div style="text-align: center; padding: 40px; color: #94a3b8;">No attacker data available</div>';
//             return;
//         }
        
//         container.innerHTML = attackers.map(attacker => `
//             <div class="top-attacker-item">
//                 <div class="attacker-ip">${attacker.ip} ${attacker.country !== 'Unknown' ? `[${attacker.country}]` : ''}</div>
//                 <div class="attacker-stats">
//                     <span><i class="fas fa-exclamation-triangle"></i> ${attacker.count} attacks</span>
//                     <span style="color: #dc2626;"><i class="fas fa-fire"></i> ${attacker.critical} critical</span>
//                     <span style="color: #f59e0b;"><i class="fas fa-bolt"></i> ${attacker.high} high</span>
//                     ${attacker.is_blacklisted ? '<span style="color: #ef4444;"><i class="fas fa-ban"></i> Blacklisted</span>' : ''}
//                 </div>
//             </div>
//         `).join('');
//     } catch (error) {
//         console.error('Error loading top attackers:', error);
//     }
// }

// Top attackers (Enhanced UI)
async function loadTopAttackers() {
    try {
        const attackers = await fetch('/api/top/attackers').then(r => r.json());
        const container = document.getElementById('top-attackers-list');

        if (!attackers || attackers.length === 0) {
            container.innerHTML = `
                <div style="text-align:center; padding:40px; color:#94a3b8;">
                    <i class="fas fa-shield-alt" style="font-size:28px; opacity:0.5;"></i><br>
                    No attacker data available
                </div>`;
            return;
        }

        container.innerHTML = attackers.map(attacker => `
            <div class="top-attacker-item">
                <div class="attacker-ip">
                    <span>${attacker.ip}</span>
                    ${attacker.country !== 'Unknown'
                        ? `<span class="country-badge">${attacker.country}</span>`
                        : ''}
                </div>

                <div class="attacker-stats">
                    <div class="stat">
                        <i class="fas fa-exclamation-triangle"></i>
                        ${attacker.count} attacks
                    </div>

                    <div class="stat critical">
                        <i class="fas fa-fire"></i>
                        ${attacker.critical} critical
                    </div>

                    <div class="stat high">
                        <i class="fas fa-bolt"></i>
                        ${attacker.high} high
                    </div>

                    ${attacker.is_blacklisted
                        ? `<div class="blacklisted">
                            <i class="fas fa-ban"></i> Blacklisted
                           </div>`
                        : ''}
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading top attackers:', error);
    }
}



// Model performance
async function loadModelPerformance() {
    try {
        const performance = await fetch('/api/model/performance').then(r => r.json());
        const container = document.getElementById('model-performance-list');
        
        if (performance.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #94a3b8;">No performance data available</div>';
            return;
        }
        
        container.innerHTML = performance.map(model => `
            <div style="background: rgba(15, 23, 42, 0.6); padding: 20px; border-radius: 15px; border: 1px solid rgba(96, 165, 250, 0.3);">
                <h3 style="color: #60a5fa; margin-bottom: 15px; font-size: 1.2em;">${model.model}</h3>
                <div style="display: grid; gap: 10px;">
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: #94a3b8;">Total Detections:</span>
                        <strong>${model.total_detections}</strong>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: #94a3b8;">High Confidence Rate:</span>
                        <strong>${model.high_confidence_rate.toFixed(1)}%</strong>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: #94a3b8;">Critical Rate:</span>
                        <strong>${model.critical_rate.toFixed(1)}%</strong>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: #94a3b8;">Avg Confidence:</span>
                        <strong>${model.avg_confidence}%</strong>
                    </div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading model performance:', error);
    }
}

// Export data
function exportData() {
    window.location.href = '/api/export/csv';
}

// Notifications
function showNotification(message, type) {
    console.log(`[${type}] ${message}`);
    // You can add a toast notification library here
}