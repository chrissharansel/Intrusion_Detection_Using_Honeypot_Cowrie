"""
Integrated IDS Engine - Uses Trained ML Model with Cowrie Data
Combines trained NSL-KDD/UNSW-NB15 model with live Cowrie honeypot logs
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
from typing import Dict, List, Callable, Optional

from cowrie_monitor import CowrieMonitor
from cowrie_feature_mapper import CowrieToNSLKDDMapper


CLOUD_MODE = os.environ.get("CLOUD_MODE", "false").lower() == "true"


class IntegratedIDSEngine:
    """
    IDS Engine that uses trained ML model with Cowrie honeypot data
    Bridges Cowrie logs to NSL-KDD features for model prediction
    """
    
    def __init__(self, cowrie_host: str, cowrie_user: str, cowrie_key: str,
                model_dir: str = 'models', model_name: str = None):
        """
        Initialize Integrated IDS Engine
        
        Args:
            cowrie_host: Cowrie honeypot hostname/IP
            cowrie_user: SSH username
            cowrie_key: Path to SSH private key
            model_dir: Directory containing trained models
            model_name: Specific model to use (e.g., 'random_forest', 'xgboost')
                    If None, uses best_model_info.json
        """

        # Initialize components
        self.cowrie_monitor = CowrieMonitor(cowrie_host, cowrie_user, cowrie_key)
        self.feature_mapper = CowrieToNSLKDDMapper()
        
        if CLOUD_MODE:
            print("☁ Running in CLOUD MODE (Cowrie disabled)")
        else:
            self.cowrie_monitor.connect()
        # Load trained model
        self.model = None
        self.scaler = None
        self.feature_columns = []
        self.model_info = {}
        self.model_dir = model_dir
        self.model_name_override = model_name  # Store the override
        self._load_trained_model()

        
        # Attack classification mapping
        self.attack_types = {
            'brute_force': ['num_failed_logins >= 5'],
            'command_injection': ['num_compromised > 0', 'root_shell == 1'],
            'malware_download': ['num_file_creations > 0', 'dst_bytes > 10000'],
            'reconnaissance': ['count > 10', 'duration < 5'],
            'dos': ['count > 50', 'srv_count > 30'],
        }
        
        # Statistics tracking
        self.stats = {
            'total_events': 0,
            'total_sessions': 0,
            'attacks_detected': 0,
            'normal_sessions': 0,
            'unique_attackers': set(),
            'attack_types': defaultdict(int),
            'severity_counts': defaultdict(int),
            'model_predictions': {'attack': 0, 'normal': 0},
            'confidence_scores': [],
            'hourly_activity': defaultdict(int)
        }
        
        # Real-time data storage
        self.recent_incidents = deque(maxlen=1000)
        self.session_predictions = {}
        
        # Alert callbacks
        self.alert_callbacks = []
        
        # System state
        self.start_time = None
        self.is_running = False
        self.cleanup_thread = None


    # def _load_trained_model(self):
    #     """Load the trained ML model and preprocessing components"""
    #     print("\n" + "="*70)
    #     print("🤖 LOADING TRAINED ML MODEL")
    #     print("="*70)
        
    #     try:
    #         # Load model info
    #         info_path = f"{self.model_dir}/best_model_info.json"
    #         with open(info_path, 'r') as f:
    #             self.model_info = json.load(f)
            
    #         print(f"✓ Model Info Loaded")
    #         print(f"  Model: {self.model_info['name']}")
    #         print(f"  Dataset: {self.model_info['dataset']}")
    #         print(f"  Features: {self.model_info['num_features']}")
    #         print(f"  Accuracy: {self.model_info['metrics']['Accuracy']*100:.2f}%")
    #         print(f"  F1-Score: {self.model_info['metrics']['F1-Score']*100:.2f}%")
            
    #         # Load model
    #         model_name = self.model_info['name'].replace(' ', '_').lower()
    #         model_path = f"{self.model_dir}/{model_name}.pkl"
    #         self.model = joblib.load(model_path)
    #         print(f"✓ Model Loaded: {model_path}")
            
    #         # Load scaler
    #         scaler_path = f"{self.model_dir}/scaler.pkl"
    #         self.scaler = joblib.load(scaler_path)
    #         print(f"✓ Scaler Loaded: {scaler_path}")
            
    #         # Load feature columns
    #         features_path = f"{self.model_dir}/feature_columns.pkl"
    #         self.feature_columns = joblib.load(features_path)
    #         print(f"✓ Feature Columns Loaded: {len(self.feature_columns)} features")
            
    #         print("\n✅ ML Model ready for predictions")
            
    #     except FileNotFoundError as e:
    #         print(f"\n❌ Model files not found!")
    #         print(f"   Error: {e}")
    #         print("\n💡 Please train a model first using ml_training_pipeline.py")
    #         print("   Place trained models in the 'models/' directory")
    #         raise
    #     except Exception as e:
    #         print(f"\n❌ Error loading model: {e}")
    #         raise
    

    def _load_trained_model(self):
        """Load the trained ML model and preprocessing components"""
        print("\n" + "="*70)
        print("🤖 LOADING TRAINED ML MODEL")
        print("="*70)
        
        try:
            # Determine which model to load
            if self.model_name_override:
                # Use specified model
                model_name = self.model_name_override
                print(f"✓ Using specified model: {model_name}")
                
                # Load corresponding info if exists
                info_path = f"{self.model_dir}/{model_name}_info.json"
                try:
                    with open(info_path, 'r') as f:
                        self.model_info = json.load(f)
                except FileNotFoundError:
                    print(f"⚠ No info file found for {model_name}, using defaults")
                    self.model_info = {'name': model_name, 'metrics': {}}
            else:
                # Use best model (default behavior)
                info_path = f"{self.model_dir}/best_model_info.json"
                with open(info_path, 'r') as f:
                    self.model_info = json.load(f)
                model_name = self.model_info['name'].replace(' ', '_').lower()
                print(f"✓ Using best model: {self.model_info['name']}")
            
            # Display model info
            print(f"  Model: {self.model_info.get('name', model_name)}")
            if 'dataset' in self.model_info:
                print(f"  Dataset: {self.model_info['dataset']}")
            if 'metrics' in self.model_info:
                metrics = self.model_info['metrics']
                if 'Accuracy' in metrics:
                    print(f"  Accuracy: {metrics['Accuracy']*100:.2f}%")
                if 'F1-Score' in metrics:
                    print(f"  F1-Score: {metrics['F1-Score']*100:.2f}%")
            
            # Load model file
            model_path = f"{self.model_dir}/{model_name}.pkl"
            self.model = joblib.load(model_path)
            print(f"✓ Model Loaded: {model_path}")
            
            # Load scaler and features (same for all models)
            scaler_path = f"{self.model_dir}/scaler.pkl"
            self.scaler = joblib.load(scaler_path)
            print(f"✓ Scaler Loaded: {scaler_path}")
            
            features_path = f"{self.model_dir}/feature_columns.pkl"
            self.feature_columns = joblib.load(features_path)
            print(f"✓ Feature Columns Loaded: {len(self.feature_columns)} features")
            
            print("\n✅ ML Model ready for predictions")
            
        except FileNotFoundError as e:
            print(f"\n❌ Model files not found!")
            print(f"   Error: {e}")
            raise
        except Exception as e:
            print(f"\n❌ Error loading model: {e}")
            raise

    # def _load_trained_model(self):
    #     print("\n" + "="*70)
    #     print("🤖 LOADING TRAINED ML MODEL (SAFE MODE)")
    #     print("="*70)

    #     with open(f"{self.model_dir}/best_model_info.json", "r") as f:
    #         self.model_info = json.load(f)

    #     model_name = self.model_info['name']
    #     print(f"✓ Best Model: {model_name}")

    #     # 🔥 FIX: Safe model loading
    #     if model_name == "XGBoost":
    #         from xgboost import XGBClassifier
    #         self.model = XGBClassifier()
    #         self.model.load_model(f"{self.model_dir}/xgboost.json")
    #         print("✓ XGBoost model loaded safely")
    #     else:
    #         model_file = model_name.replace(" ", "_").lower() + ".pkl"
    #         self.model = joblib.load(f"{self.model_dir}/{model_file}")
    #         print(f"✓ Model loaded: {model_file}")

    #     self.scaler = joblib.load(f"{self.model_dir}/scaler.pkl")
    #     self.feature_columns = joblib.load(f"{self.model_dir}/feature_columns.pkl")
    #     self.label_encoders = joblib.load(f"{self.model_dir}/label_encoders.pkl")

    #     print("✓ Scaler, encoders, features loaded")
    #     print("✅ MODEL READY FOR LIVE INFERENCE")


    # def start(self) -> bool:
    #     """Start the IDS engine"""
    #     print("\n" + "="*70)
    #     print("🛡️  INTEGRATED IDS STARTING")
    #     print("="*70)
        
    #     self.start_time = datetime.now()
        
    #     # Connect to Cowrie
    #     print("\n🔌 Connecting to Cowrie honeypot...")
    #     if not self.cowrie_monitor.connect():
    #         print("❌ Failed to connect to Cowrie")
    #         return False
        
    #     if not self.cowrie_monitor.test_connection():
    #         print("❌ Connection test failed")
    #         return False
        
    #     # Process historical data
    #     print("\n📊 Loading and analyzing historical data...")
    #     historical_events = self.cowrie_monitor.get_historical_logs(500)
        
    #     # Process historical events
    #     for event in historical_events:
    #         self._process_event(event, is_historical=True)
        
    #     print(f"✓ Processed {len(historical_events)} historical events")
    #     print(f"✓ Detected {self.stats['attacks_detected']} attacks")
    #     print(f"✓ Model confidence avg: {np.mean(self.stats['confidence_scores']):.2%}" 
    #           if self.stats['confidence_scores'] else "")
        
    #     # Start real-time monitoring
    #     print("\n🔴 Starting real-time monitoring...")
    #     self.is_running = True
    #     self.cowrie_monitor.start_monitoring(self._on_new_event)
        
    #     # Start cleanup thread
    #     self.cleanup_thread = threading.Thread(
    #         target=self._cleanup_old_sessions,
    #         daemon=True
    #     )
    #     self.cleanup_thread.start()
        
    #     print("✓ IDS Engine active and monitoring")
    #     print("\n" + "="*70)
        
    #     return True
    def start(self) -> bool:
        print("\n" + "="*70)
        print("🛡️  INTEGRATED IDS STARTING")
        print("="*70)

        self.start_time = datetime.now()

        if not CLOUD_MODE:
            print("\n🔌 Connecting to Cowrie honeypot...")
            if not self.cowrie_monitor.connect():
                print("❌ Failed to connect to Cowrie")
                return False

            if not self.cowrie_monitor.test_connection():
                print("❌ Connection test failed")
                return False

            print("\n📊 Loading and analyzing historical data...")
            historical_events = self.cowrie_monitor.get_historical_logs(500)

            for event in historical_events:
                self._process_event(event, is_historical=True)

            print(f"✓ Processed {len(historical_events)} historical events")

            print("\n🔴 Starting real-time monitoring...")
            self.is_running = True
            self.cowrie_monitor.start_monitoring(self._on_new_event)

        else:
            # CLOUD MODE
            print("☁ Cowrie disabled — running in SIMULATION / API mode")
            self.is_running = True

        # Cleanup thread works in both modes
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_old_sessions,
            daemon=True
        )
        self.cleanup_thread.start()

        print("✓ IDS Engine active")
        print("\n" + "="*70)

        return True

    
    def _on_new_event(self, event: Dict):
        """Callback for new Cowrie events"""
        self._process_event(event, is_historical=False)
    
    def _process_event(self, event: Dict, is_historical: bool = False):
        """Process Cowrie event through the ML model"""
        try:
            self.stats['total_events'] += 1
            session_id = event.get('session', 'unknown')
            
            # Map Cowrie event to NSL-KDD features
            features = self.feature_mapper.process_cowrie_event(event)
            
            # Create feature vector for model
            feature_vector = self._prepare_feature_vector(features)
            
            # Make prediction
            prediction_result = self._predict(feature_vector, features)
            
            # Store prediction for this session
            self.session_predictions[session_id] = prediction_result
            
            # Update statistics
            self._update_statistics(event, features, prediction_result)
            
            # Handle attack detection
            if prediction_result['is_attack']:
                self._handle_attack(event, features, prediction_result, is_historical)
            else:
                self.stats['normal_sessions'] += 1
                
        except Exception as e:
            print(f"⚠ Error processing event: {e}")
    


    def _prepare_feature_vector(self, features: Dict) -> np.ndarray:
        """
        Prepare feature vector for model prediction
        
        Args:
            features: NSL-KDD formatted features
            
        Returns:
            Numpy array ready for model input
        """
        # Create feature vector in correct order
        feature_values = []
        
        for col in self.feature_columns:
            value = features.get(col, 0)
            
            # Handle categorical features (if any)
            if isinstance(value, str):
                # Simple hash encoding for categorical
                value = hash(value) % 1000
            
            feature_values.append(float(value))
        
        return pd.DataFrame(
                [feature_values],
                columns=self.feature_columns
            )

    

    # def _prepare_feature_vector(self, features: Dict) -> pd.DataFrame:
    #     """Prepare feature vector EXACTLY like training"""
    #     row = {}

    #     for col in self.feature_columns:
    #         val = features.get(col, 0)

    #         # 🔥 FIX: Use SAME LabelEncoder as training
    #         if col in self.label_encoders:
    #             le = self.label_encoders[col]
    #             val = le.transform([val])[0] if val in le.classes_ else 0

    #         row[col] = float(val)

    #     return pd.DataFrame([row])




    def _predict(self, feature_vector: np.ndarray, features: Dict) -> Dict:
        """
        Make prediction using trained model
        
        Args:
            feature_vector: Prepared feature vector
            features: Original features for rule-based enhancement
            
        Returns:
            Prediction result dictionary
        """
        try:
            # Scale features
            scaled_features = self.scaler.transform(feature_vector)
            
            # Predict
            prediction = self.model.predict(scaled_features)[0]
            
            # Get probability if available
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(scaled_features)[0]
                confidence = max(probabilities)
                attack_probability = probabilities[1] if len(probabilities) > 1 else probabilities[0]
            else:
                confidence = 0.75
                attack_probability = 0.8 if prediction == 1 else 0.2
            
            # Classify attack type based on features
            attack_type = self._classify_attack_type(features)
            severity = self._calculate_severity(features, attack_probability)
            
            return {
                'is_attack': bool(prediction),
                'confidence': float(confidence),
                'attack_probability': float(attack_probability),
                'attack_type': attack_type,
                'severity': severity,
                'method': 'ML Model',
                'model_name': self.model_info.get('name', 'Unknown'),
                'features': features
            }
            
        except Exception as e:
            print(f"⚠ Prediction error: {e}")
            # Fallback to simple rule-based
            return {
                'is_attack': features.get('num_failed_logins', 0) > 5,
                'confidence': 0.5,
                'attack_probability': 0.5,
                'attack_type': 'Unknown',
                'severity': 'Medium',
                'method': 'Fallback',
                'model_name': 'Rule-based',
                'features': features
            }
    
    # def _predict(self, feature_df: pd.DataFrame, features: Dict) -> Dict:
    #     try:
    #         # 🔥 FIX: Preserve feature names
    #         scaled = self.scaler.transform(feature_df)

    #         pred = self.model.predict(scaled)[0]

    #         if hasattr(self.model, "predict_proba"):
    #             proba = self.model.predict_proba(scaled)[0]
    #             attack_prob = float(proba[1])
    #             confidence = max(proba)
    #         else:
    #             attack_prob = 0.8 if pred == 1 else 0.2
    #             confidence = 0.75

    #         # 🔥 FIX: Robust attack decision
    #         if isinstance(pred, (int, np.integer)):
    #             is_attack = pred == 1
    #         elif isinstance(pred, str):
    #             is_attack = pred.lower() != "normal"
    #         else:
    #             is_attack = False

    #         return {
    #             "is_attack": is_attack,
    #             "confidence": confidence,
    #             "attack_probability": attack_prob,
    #             "attack_type": self._classify_attack_type(features),
    #             "severity": self._calculate_severity(features, attack_prob),
    #             "method": "ML Model",
    #             "model_name": self.model_info["name"],
    #             "features": features
    #         }

    #     except Exception as e:
    #         print(f"⚠ ML FAILED — fallback used: {e}")
    #         return {
    #             "is_attack": features.get("num_failed_logins", 0) > 5,
    #             "confidence": 0.5,
    #             "attack_probability": 0.5,
    #             "attack_type": "Rule-Based",
    #             "severity": "Medium",
    #             "method": "Fallback",
    #             "model_name": "Rule Engine",
    #             "features": features
    #         }




    def _classify_attack_type(self, features: Dict) -> str:
        """Classify specific attack type based on features"""
        
        # SSH Brute Force
        if features.get('num_failed_logins', 0) >= 5:
            return 'SSH Brute Force'
        
        # Command Injection / Exploitation
        if features.get('num_compromised', 0) > 0 or features.get('root_shell', 0) == 1:
            return 'Command Injection'
        
        # Malware Download
        if features.get('num_file_creations', 0) > 0 and features.get('dst_bytes', 0) > 10000:
            return 'Malware Download'
        
        # DoS / Flooding
        if features.get('count', 0) > 50:
            return 'DoS Attack'
        
        # Port Scan / Reconnaissance
        if features.get('count', 0) > 10 and features.get('duration', 0) < 5:
            return 'Port Scan'
        
        # Credential Stuffing
        if features.get('is_guest_login', 0) == 1 or features.get('num_failed_logins', 0) > 10:
            return 'Credential Stuffing'
        
        # Default
        return 'Suspicious Activity'
    
    def _calculate_severity(self, features: Dict, attack_prob: float) -> str:
        """Calculate attack severity"""
        severity_score = 0
        
        # Failed logins
        if features.get('num_failed_logins', 0) > 10:
            severity_score += 3
        elif features.get('num_failed_logins', 0) > 5:
            severity_score += 2
        
        # Compromise indicators
        if features.get('num_compromised', 0) > 0:
            severity_score += 4
        
        # Root access
        if features.get('root_shell', 0) == 1:
            severity_score += 4
        
        # File operations
        if features.get('num_file_creations', 0) > 3:
            severity_score += 2
        
        # Attack probability from model
        if attack_prob > 0.95:
            severity_score += 3
        elif attack_prob > 0.85:
            severity_score += 2
        elif attack_prob > 0.70:
            severity_score += 1
        
        # Map to severity levels
        if severity_score >= 8:
            return 'Critical'
        elif severity_score >= 5:
            return 'High'
        elif severity_score >= 3:
            return 'Medium'
        else:
            return 'Low'
    
    def _update_statistics(self, event: Dict, features: Dict, prediction: Dict):
        """Update system statistics"""
        
        # Track predictions
        if prediction['is_attack']:
            self.stats['model_predictions']['attack'] += 1
        else:
            self.stats['model_predictions']['normal'] += 1
        
        # Track confidence
        self.stats['confidence_scores'].append(prediction['confidence'])
        if len(self.stats['confidence_scores']) > 1000:
            self.stats['confidence_scores'] = self.stats['confidence_scores'][-1000:]
        
        # Track unique IPs
        src_ip = event.get('src_ip')
        if src_ip:
            self.stats['unique_attackers'].add(src_ip)
        
        # Track hourly activity
        try:
            timestamp = datetime.fromisoformat(
                event.get('timestamp', '').replace('Z', '+00:00')
            )
            hour = timestamp.hour
            self.stats['hourly_activity'][hour] += 1
        except:
            pass
    
    def _handle_attack(self, event: Dict, features: Dict, 
                      prediction: Dict, is_historical: bool):
        """Handle detected attack"""
        
        self.stats['attacks_detected'] += 1
        
        # Update attack type statistics
        attack_type = prediction['attack_type']
        self.stats['attack_types'][attack_type] += 1
        
        # Update severity statistics
        severity = prediction['severity']
        self.stats['severity_counts'][severity] += 1
        
        # Create incident record
        incident = self._create_incident(event, features, prediction)
        
        # Store incident
        self.recent_incidents.append(incident)
        
        # Trigger alerts (only for new events)
        if not is_historical:
            self._trigger_alerts(incident)
    
    def _create_incident(self, event: Dict, features: Dict, 
                        prediction: Dict) -> Dict:
        """Create incident record"""
        
        return {
            'timestamp': event.get('timestamp', ''),
            'src_ip': event.get('src_ip', ''),
            'session': event.get('session', ''),
            'attack_type': prediction['attack_type'],
            'severity': prediction['severity'],
            'confidence': prediction['confidence'],
            'attack_probability': prediction['attack_probability'],
            'method': prediction['method'],
            'model_name': prediction['model_name'],
            'details': {
                'eventid': event.get('eventid', ''),
                'failed_logins': features.get('num_failed_logins', 0),
                'successful_logins': 1 if features.get('logged_in', 0) == 1 else 0,
                'commands': features.get('num_shells', 0),
                'duration': features.get('duration', 0),
                'bytes_transferred': features.get('src_bytes', 0) + features.get('dst_bytes', 0),
                'username': event.get('username', ''),
                'command': event.get('input', ''),
                'nsl_kdd_features': {
                    'hot': features.get('hot', 0),
                    'num_compromised': features.get('num_compromised', 0),
                    'root_shell': features.get('root_shell', 0),
                    'count': features.get('count', 0)
                }
            }
        }
    
    def _trigger_alerts(self, incident: Dict):
        """Trigger alert callbacks"""
        for callback in self.alert_callbacks:
            try:
                callback(incident)
            except Exception as e:
                print(f"❌ Alert callback error: {e}")
    
    def _cleanup_old_sessions(self):
        """Periodically cleanup old session data"""
        while self.is_running:
            time.sleep(300)  # Every 5 minutes
            try:
                self.feature_mapper.clear_old_sessions(max_age_seconds=3600)
            except Exception as e:
                print(f"⚠ Session cleanup error: {e}")
    
    def register_alert_callback(self, callback: Callable[[Dict], None]):
        """Register callback for alerts"""
        self.alert_callbacks.append(callback)
        print(f"✓ Registered alert callback: {callback.__name__}")
    


    # def get_stats(self) -> Dict:
    #     """Get current statistics (derived, model-safe)"""

    #     total_events = self.stats.get('total_events', 0)

    #     attack_count = self.stats.get('model_predictions', {}).get('attack', 0)
    #     normal_count = self.stats.get('model_predictions', {}).get('normal', 0)

    #     total_predictions = attack_count + normal_count

    #     attack_rate = (
    #         round((attack_count / total_events) * 100, 2)
    #         if total_events > 0 else 0
    #     )

    #     avg_confidence = (
    #         round(float(np.mean(self.stats['confidence_scores'])), 4)
    #         if self.stats.get('confidence_scores') else 0
    #     )

    #     return {
    #         'total_events': total_events,
    #         'attacks_detected': attack_count,
    #         'normal_sessions': normal_count,
    #         'attack_rate': attack_rate,
    #         'unique_attackers': len(self.stats.get('unique_attackers', set())),
    #         'attack_types': dict(self.stats.get('attack_types', {})),
    #         'severity_counts': dict(self.stats.get('severity_counts', {})),
    #         'model_predictions': {
    #             'attack': attack_count,
    #             'normal': normal_count
    #         },
    #         'avg_confidence': avg_confidence,
    #         'hourly_activity': dict(self.stats.get('hourly_activity', {})),
    #         'uptime_seconds': (
    #             (datetime.now() - self.start_time).total_seconds()
    #             if self.start_time else 0
    #         ),
    #         'model_info': {
    #             'name': self.model_info.get('name', 'Unknown'),
    #             'accuracy': self.model_info.get('metrics', {}).get('Accuracy', 0),
    #             'f1_score': self.model_info.get('metrics', {}).get('F1-Score', 0)
    #         }
    #     }


    def get_stats(self) -> Dict:
        """Get current statistics"""
        total_predictions = max(sum(self.stats['model_predictions'].values()), 1)
        
        return {
            'total_events': self.stats['total_events'],
            'attacks_detected': self.stats['attacks_detected'],
            'normal_sessions': self.stats['normal_sessions'],
            'attack_rate': round((self.stats['attacks_detected'] / total_predictions) * 100, 2),
            'unique_attackers': len(self.stats['unique_attackers']),
            'attack_types': dict(self.stats['attack_types']),
            'severity_counts': dict(self.stats['severity_counts']),
            'model_predictions': dict(self.stats['model_predictions']),
            'avg_confidence': round(np.mean(self.stats['confidence_scores']), 4) 
                            if self.stats['confidence_scores'] else 0,
            'hourly_activity': dict(self.stats['hourly_activity']),
            'uptime_seconds': (datetime.now() - self.start_time).total_seconds() 
                             if self.start_time else 0,
            'model_info': {
                'name': self.model_info.get('name', 'Unknown'),
                'accuracy': self.model_info.get('metrics', {}).get('Accuracy', 0),
                'f1_score': self.model_info.get('metrics', {}).get('F1-Score', 0)
            }
        }
    
    def get_recent_incidents(self, limit: int = 50) -> List[Dict]:
        """Get recent incidents"""
        return list(self.recent_incidents)[-limit:][::-1]
    
    def stop(self):
        """Stop the IDS engine"""
        print("\n🛑 Stopping IDS Engine...")
        
        self.is_running = False
        self.cowrie_monitor.stop()
        self.cowrie_monitor.disconnect()
        
        # Final statistics
        print("\n📊 Final Statistics:")
        stats = self.get_stats()
        print(f"   • Total Events: {stats['total_events']}")
        print(f"   • Attacks Detected: {stats['attacks_detected']}")
        print(f"   • Attack Rate: {stats['attack_rate']}%")
        print(f"   • Unique Attackers: {stats['unique_attackers']}")
        print(f"   • Model: {stats['model_info']['name']}")
        print(f"   • Avg Confidence: {stats['avg_confidence']:.2%}")
        
        print("\n✓ IDS Engine stopped")

