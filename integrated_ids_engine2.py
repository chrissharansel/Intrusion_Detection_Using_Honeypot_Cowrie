"""
Integrated IDS Engine - FIXED VERSION
✔ Real-time Cowrie monitoring
✔ ML + Rule-based hybrid detection
✔ Proper command injection detection
✔ Stable feature handling
"""

import os
import time
import threading
import joblib
import json
import numpy as np
import pandas as pd
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Callable

from cowrie_monitor import CowrieMonitor
from cowrie_feature_mapper import CowrieToNSLKDDMapper


class IntegratedIDSEngine:

    def __init__(self, host, username, key_file, model_dir="models"):
        self.cowrie_monitor = CowrieMonitor(host, username, key_file)
        self.feature_mapper = CowrieToNSLKDDMapper()

        # ML components
        self.model = None
        self.scaler = None
        self.feature_columns = []

        # State
        self.is_running = False
        self.start_time = None

        # Storage
        self.recent_incidents = deque(maxlen=1000)
        self.alert_callbacks = []

        # Stats
        self.stats = {
            'total_events': 0,
            'attacks_detected': 0,
            'normal_sessions': 0,
            'attack_types': defaultdict(int),
            'severity_counts': defaultdict(int),
        }

        self._load_model(model_dir)

    # =========================
    # LOAD MODEL
    # =========================
    def _load_model(self, model_dir):
        print("\n🤖 Loading ML Model...")

        self.model = joblib.load(os.path.join(model_dir, "lightgbm.pkl"))
        self.scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
        self.feature_columns = joblib.load(os.path.join(model_dir, "feature_columns.pkl"))

        print("✅ Model + scaler + features loaded")

    # =========================
    # START ENGINE
    # =========================
    def start(self):
        print("\n🛡️ IDS STARTING")

        if not self.cowrie_monitor.connect():
            return False

        self.start_time = datetime.now()

        # Load historical
        events = self.cowrie_monitor.get_historical_logs(200)
        for e in events:
            self._process_event(e, True)

        print(f"✓ Loaded {len(events)} historical events")

        # Start real-time
        self.is_running = True
        self.cowrie_monitor.start_monitoring(self._process_event)

        print("✓ IDS ACTIVE")
        return True

    # =========================
    # MAIN PROCESSOR
    # =========================
    def _process_event(self, event, is_historical=False):
        try:
            self.stats['total_events'] += 1

            # Extract features
            features = self.feature_mapper.process_cowrie_event(event)

            # 🔥 IMPORTANT: keep command
            command = event.get("input", "")
            features["command"] = command

            # ML prediction
            prediction = self._predict(features)

            # Rule override (CRITICAL FIX)
            if self._detect_command_injection(command):
                prediction["is_attack"] = True
                prediction["attack_type"] = "Command Injection"
                prediction["severity"] = "High"

            if prediction["is_attack"]:
                self.stats['attacks_detected'] += 1
                self.stats['attack_types'][prediction["attack_type"]] += 1
                self.stats['severity_counts'][prediction["severity"]] += 1

                incident = self._create_incident(event, prediction)
                self.recent_incidents.append(incident)

                if not is_historical:
                    self._trigger_alerts(incident)

            else:
                self.stats['normal_sessions'] += 1

        except Exception as e:
            print("❌ PROCESS ERROR:", e)

    # =========================
    # ML PREDICTION (FIXED)
    # =========================
    def _predict(self, features):
        try:
            row = {col: float(features.get(col, 0)) for col in self.feature_columns}
            df = pd.DataFrame([row])

            scaled = self.scaler.transform(df)
            pred = self.model.predict(scaled)[0]

            proba = self.model.predict_proba(scaled)[0]
            confidence = float(max(proba))

            return {
                "is_attack": bool(pred),
                "confidence": confidence,
                "attack_type": "ML Detected",
                "severity": "Medium"
            }

        except Exception as e:
            print("⚠ ML ERROR:", e)
            return {
                "is_attack": False,
                "confidence": 0.5,
                "attack_type": "Unknown",
                "severity": "Low"
            }

    # =========================
    # 🔥 COMMAND INJECTION DETECTION (FIX)
    # =========================
    def _detect_command_injection(self, cmd):
        patterns = [
            ";", "&&", "|", "`", "$(",
            "wget", "curl", "nc",
            "bash", "sh", "python", "perl"
        ]
        return any(p in cmd for p in cmd and patterns)

    # =========================
    # INCIDENT CREATION
    # =========================
    def _create_incident(self, event, pred):
        return {
            "timestamp": event.get("timestamp"),
            "src_ip": event.get("src_ip"),
            "command": event.get("input"),
            "attack_type": pred["attack_type"],
            "severity": pred["severity"],
            "confidence": pred["confidence"]
        }

    # =========================
    # ALERT CALLBACK
    # =========================
    def register_alert_callback(self, cb):
        self.alert_callbacks.append(cb)

    def _trigger_alerts(self, incident):
        for cb in self.alert_callbacks:
            cb(incident)

    # =========================
    # STATS
    # =========================
    def get_stats(self):
        return {
            "total_events": self.stats['total_events'],
            "attacks_detected": self.stats['attacks_detected'],
            "normal_sessions": self.stats['normal_sessions'],
            "attack_types": dict(self.stats['attack_types']),
            "severity_counts": dict(self.stats['severity_counts']),
        }

    def get_recent_incidents(self, limit=50):
        return list(self.recent_incidents)[-limit:]

    # =========================
    # STOP
    # =========================
    def stop(self):
        self.is_running = False
        self.cowrie_monitor.stop()
        self.cowrie_monitor.disconnect()
        print("🛑 IDS STOPPED")