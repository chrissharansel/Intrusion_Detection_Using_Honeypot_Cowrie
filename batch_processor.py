"""
Batch Cowrie Log Processor
Processes Cowrie JSON logs through trained ML model and generates reports
"""

import pandas as pd
import numpy as np
import joblib
import json
import sys
from datetime import datetime
from collections import defaultdict
from cowrie_feature_mapper import CowrieToNSLKDDMapper
from typing import Dict


class CowrieBatchProcessor:
    """
    Batch process Cowrie logs through trained ML model
    Generates detailed analysis and reports
    """
    
    def __init__(self, model_dir: str = 'models'):
        """
        Initialize batch processor
        
        Args:
            model_dir: Directory containing trained models
        """
        self.model_dir = model_dir
        self.mapper = CowrieToNSLKDDMapper()
        self.model = None
        self.scaler = None
        self.feature_columns = []
        self.model_info = {}
        
        # Load model
        self._load_model()
    
    def _load_model(self):
        """Load trained model and preprocessors"""
        print("\n🤖 Loading ML Model...")
        
        try:
            # Load model info
            with open(f"{self.model_dir}/best_model_info.json", 'r') as f:
                self.model_info = json.load(f)
            
            # Load model
            model_name = self.model_info['name'].replace(' ', '_').lower()
            self.model = joblib.load(f"{self.model_dir}/{model_name}.pkl")
            
            # Load scaler
            self.scaler = joblib.load(f"{self.model_dir}/scaler.pkl")
            
            # Load features
            self.feature_columns = joblib.load(f"{self.model_dir}/feature_columns.pkl")
            
            print(f"✓ Loaded: {self.model_info['name']}")
            print(f"  Accuracy: {self.model_info['metrics']['Accuracy']*100:.2f}%")
            print(f"  F1-Score: {self.model_info['metrics']['F1-Score']*100:.2f}%")
            
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            raise
    
    def process_log_file(self, log_file: str) -> pd.DataFrame:
        """
        Process entire Cowrie log file
        
        Args:
            log_file: Path to cowrie.json file
            
        Returns:
            DataFrame with predictions and analysis
        """
        print(f"\n{'='*70}")
        print(f"📁 PROCESSING: {log_file}")
        print(f"{'='*70}")
        
        # Map to NSL-KDD features
        print("\n🔄 Mapping Cowrie events to NSL-KDD features...")
        features_df = self.mapper.process_cowrie_log_file(log_file)
        
        if features_df.empty:
            print("❌ No data to process")
            return pd.DataFrame()
        
        # Make predictions
        print(f"\n🎯 Making predictions on {len(features_df)} sessions...")
        predictions = self._predict_batch(features_df)
        
        # Combine features and predictions
        results_df = features_df.copy()
        results_df['prediction'] = predictions['prediction']
        results_df['attack_probability'] = predictions['attack_probability']
        results_df['attack_type'] = predictions['attack_type']
        results_df['severity'] = predictions['severity']
        
        print(f"✓ Predictions complete")
        
        return results_df
    
    def _predict_batch(self, features_df: pd.DataFrame) -> Dict:
        """Make batch predictions"""
        
        # Prepare features
        X = features_df[self.feature_columns].values
        
        # Scale
        X_scaled = self.scaler.transform(X)
        
        # Predict
        predictions = self.model.predict(X_scaled)
        
        # Get probabilities
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(X_scaled)
            attack_probs = probabilities[:, 1] if probabilities.shape[1] > 1 else probabilities[:, 0]
        else:
            attack_probs = predictions.astype(float) * 0.8
        
        # Classify attack types
        attack_types = []
        severities = []
        
        for i, (_, row) in enumerate(features_df.iterrows()):
            attack_type = self._classify_attack(row)
            attack_prob = attack_probs[i] if i < len(attack_probs) else 0.5
            severity = self._calculate_severity(row, attack_prob)
            attack_types.append(attack_type)
            severities.append(severity)

        
        return {
            'prediction': predictions,
            'attack_probability': attack_probs,
            'attack_type': attack_types,
            'severity': severities
        }
    
    def _classify_attack(self, features: pd.Series) -> str:
        """Classify attack type from features"""
        
        if features.get('num_failed_logins', 0) >= 5:
            return 'SSH Brute Force'
        elif features.get('num_compromised', 0) > 0:
            return 'Command Injection'
        elif features.get('num_file_creations', 0) > 0:
            return 'Malware Download'
        elif features.get('count', 0) > 50:
            return 'DoS Attack'
        elif features.get('count', 0) > 10:
            return 'Port Scan'
        else:
            return 'Suspicious Activity'
    
    def _calculate_severity(self, features: pd.Series, attack_prob: float) -> str:
        """Calculate severity"""
        score = 0
        
        if features.get('num_failed_logins', 0) > 10:
            score += 3
        if features.get('num_compromised', 0) > 0:
            score += 4
        if features.get('root_shell', 0) == 1:
            score += 4
        if attack_prob > 0.9:
            score += 3
        
        if score >= 8:
            return 'Critical'
        elif score >= 5:
            return 'High'
        elif score >= 3:
            return 'Medium'
        else:
            return 'Low'
    
    def generate_report(self, results_df: pd.DataFrame, output_file: str = None):
        """Generate analysis report"""
        
        print(f"\n{'='*70}")
        print("📊 ANALYSIS REPORT")
        print(f"{'='*70}")
        
        # Statistics
        total_sessions = len(results_df)
        attacks = (results_df['prediction'] == 1).sum()
        normal = (results_df['prediction'] == 0).sum()
        attack_rate = (attacks / total_sessions * 100) if total_sessions > 0 else 0
        
        print(f"\n📈 Overall Statistics:")
        print(f"  Total Sessions: {total_sessions:,}")
        print(f"  Attacks Detected: {attacks:,} ({attack_rate:.2f}%)")
        print(f"  Normal Sessions: {normal:,} ({100-attack_rate:.2f}%)")
        print(f"  Average Attack Probability: {results_df['attack_probability'].mean():.2%}")
        
        # Attack types
        if attacks > 0:
            attack_sessions = results_df[results_df['prediction'] == 1]
            
            print(f"\n🎯 Attack Types:")
            attack_type_counts = attack_sessions['attack_type'].value_counts()
            for attack_type, count in attack_type_counts.items():
                percentage = (count / attacks * 100)
                print(f"  {attack_type}: {count:,} ({percentage:.1f}%)")
            
            print(f"\n⚠️  Severity Distribution:")
            severity_counts = attack_sessions['severity'].value_counts()
            for severity, count in severity_counts.items():
                percentage = (count / attacks * 100)
                print(f"  {severity}: {count:,} ({percentage:.1f}%)")
            
            # Top indicators
            print(f"\n🔍 Key Attack Indicators:")
            print(f"  Sessions with failed logins: {(attack_sessions['num_failed_logins'] > 0).sum():,}")
            print(f"  Sessions with compromise indicators: {(attack_sessions['num_compromised'] > 0).sum():,}")
            print(f"  Sessions with root shell: {(attack_sessions['root_shell'] == 1).sum():,}")
            print(f"  Sessions with file creation: {(attack_sessions['num_file_creations'] > 0).sum():,}")
            
            # Top attackers (if we had IP data)
            print(f"\n🌐 Attack Characteristics:")
            print(f"  Avg duration: {attack_sessions['duration'].mean():.2f}s")
            print(f"  Avg failed logins: {attack_sessions['num_failed_logins'].mean():.2f}")
            print(f"  Avg bytes transferred: {(attack_sessions['src_bytes'] + attack_sessions['dst_bytes']).mean():.0f}")
        
        # Model performance
        print(f"\n🤖 Model Performance:")
        print(f"  Model: {self.model_info['name']}")
        print(f"  Training Accuracy: {self.model_info['metrics']['Accuracy']*100:.2f}%")
        print(f"  Training F1-Score: {self.model_info['metrics']['F1-Score']*100:.2f}%")
        
        # High-confidence detections
        high_conf = results_df[results_df['attack_probability'] > 0.9]
        if len(high_conf) > 0:
            print(f"\n⚡ High Confidence Detections (>90%):")
            print(f"  Count: {len(high_conf):,}")
            print(f"  Attack types: {', '.join(high_conf['attack_type'].unique())}")
        
        # Save detailed results
        if output_file:
            results_df.to_csv(output_file, index=False)
            print(f"\n💾 Detailed results saved to: {output_file}")
        
        print(f"\n{'='*70}")
        
        return {
            'total_sessions': total_sessions,
            'attacks': attacks,
            'attack_rate': attack_rate,
            'attack_types': attack_type_counts.to_dict() if attacks > 0 else {},
            'severities': severity_counts.to_dict() if attacks > 0 else {}
        }


def main():
    """Main execution"""
    
    if len(sys.argv) < 2:
        print("\n📖 Usage: python batch_processor.py <cowrie_log_file> [output_csv]")
        print("\nExample:")
        print("  python batch_processor.py cowrie.json")
        print("  python batch_processor.py cowrie.json results.csv")
        sys.exit(1)
    
    log_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    # Process
    processor = CowrieBatchProcessor(model_dir='models')
    results = processor.process_log_file(log_file)
    
    if not results.empty:
        # Generate report
        stats = processor.generate_report(results, output_file)
        
        print("\n✅ Processing complete!")
        print(f"\n💡 Next steps:")
        print(f"  1. Review {output_file} for detailed results")
        print(f"  2. Investigate high-severity incidents")
        print(f"  3. Update security policies based on findings")
    else:
        print("\n❌ No results generated")


if __name__ == "__main__":
    main()


# import paramiko
# import json
# import pandas as pd
# from cowrie_feature_mapper import CowrieToNSLKDDMapper
# from typing import Dict

# class CowrieRealTimeProcessor:
#     """
#     Real-time processor for Cowrie logs via SSH
#     Processes logs as they are written to the remote cowrie.json
#     """

#     def __init__(self, ssh_host: str, ssh_user: str, ssh_key_path: str, model_dir: str = 'models'):
#         self.ssh_host = ssh_host
#         self.ssh_user = ssh_user
#         self.ssh_key_path = ssh_key_path
#         self.remote_cowrie_path = "/var/log/cowrie/cowrie.json"

#         self.mapper = CowrieToNSLKDDMapper()
#         self.model_dir = model_dir
#         self.model = None
#         self.scaler = None
#         self.feature_columns = []
#         self.model_info = {}

#         self._load_model()
#         self._setup_ssh()

#     def _load_model(self):
#         import joblib
#         print("\n🤖 Loading ML Model...")
#         try:
#             with open(f"{self.model_dir}/best_model_info.json", 'r') as f:
#                 self.model_info = json.load(f)

#             model_name = self.model_info['name'].replace(' ', '_').lower()
#             self.model = joblib.load(f"{self.model_dir}/{model_name}.pkl")
#             self.scaler = joblib.load(f"{self.model_dir}/scaler.pkl")
#             self.feature_columns = joblib.load(f"{self.model_dir}/feature_columns.pkl")

#             print(f"✓ Loaded: {self.model_info['name']}")
#             print(f"  Accuracy: {self.model_info['metrics']['Accuracy']*100:.2f}%")
#             print(f"  F1-Score: {self.model_info['metrics']['F1-Score']*100:.2f}%")
#         except Exception as e:
#             print(f"❌ Error loading model: {e}")
#             raise

#     def _setup_ssh(self):
#         print(f"\n🔗 Connecting to {self.ssh_host} via SSH...")
#         key = paramiko.RSAKey.from_private_key_file(self.ssh_key_path)
#         self.ssh_client = paramiko.SSHClient()
#         self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         self.ssh_client.connect(hostname=self.ssh_host, username=self.ssh_user, pkey=key)
#         print("✓ SSH connection established")

#     def tail_cowrie_logs(self):
#         """Stream cowrie.json logs in real-time and process them"""
#         cmd = f"tail -F {self.remote_cowrie_path}"  # -F handles file rotation
#         stdin, stdout, stderr = self.ssh_client.exec_command(cmd)

#         print("\n⏱️  Listening to Cowrie logs in real-time...")
#         for line in stdout:
#             line = line.strip()
#             if not line:
#                 continue
#             try:
#                 log_entry = json.loads(line)
#             except json.JSONDecodeError:
#                 continue  # skip malformed lines

#             # Map single log entry to NSL-KDD features
#             features_df = self.mapper.process_cowrie_entry(log_entry)
#             if features_df.empty:
#                 continue

#             predictions = self._predict_batch(features_df)
#             features_df['prediction'] = predictions['prediction']
#             features_df['attack_probability'] = predictions['attack_probability']
#             features_df['attack_type'] = predictions['attack_type']
#             features_df['severity'] = predictions['severity']

#             # Print immediate feedback for the log
#             print(f"🚨 Session Prediction: {features_df.iloc[0]['attack_type']} "
#                   f"(Severity: {features_df.iloc[0]['severity']}, "
#                   f"Prob: {features_df.iloc[0]['attack_probability']:.2%})")

#     def _predict_batch(self, features_df: pd.DataFrame) -> Dict:
#         """Make batch predictions for one or more sessions"""
#         X = features_df[self.feature_columns].values
#         X_scaled = self.scaler.transform(X)
#         predictions = self.model.predict(X_scaled)

#         if hasattr(self.model, 'predict_proba'):
#             probabilities = self.model.predict_proba(X_scaled)
#             attack_probs = probabilities[:, 1] if probabilities.shape[1] > 1 else probabilities[:, 0]
#         else:
#             attack_probs = predictions.astype(float) * 0.8

#         attack_types, severities = [], []
#         for idx, row in features_df.iterrows():
#             attack_type = self._classify_attack(row)
#             severity = self._calculate_severity(row, attack_probs[idx])
#             attack_types.append(attack_type)
#             severities.append(severity)

#         return {
#             'prediction': predictions,
#             'attack_probability': attack_probs,
#             'attack_type': attack_types,
#             'severity': severities
#         }

#     def _classify_attack(self, features: pd.Series) -> str:
#         if features.get('num_failed_logins', 0) >= 5:
#             return 'SSH Brute Force'
#         elif features.get('num_compromised', 0) > 0:
#             return 'Command Injection'
#         elif features.get('num_file_creations', 0) > 0:
#             return 'Malware Download'
#         elif features.get('count', 0) > 50:
#             return 'DoS Attack'
#         elif features.get('count', 0) > 10:
#             return 'Port Scan'
#         else:
#             return 'Suspicious Activity'

#     def _calculate_severity(self, features: pd.Series, attack_prob: float) -> str:
#         score = 0
#         if features.get('num_failed_logins', 0) > 10:
#             score += 3
#         if features.get('num_compromised', 0) > 0:
#             score += 4
#         if features.get('root_shell', 0) == 1:
#             score += 4
#         if attack_prob > 0.9:
#             score += 3
#         if score >= 8:
#             return 'Critical'
#         elif score >= 5:
#             return 'High'
#         elif score >= 3:
#             return 'Medium'
#         else:
#             return 'Low'


# import time
# import threading
# import paramiko
# import json
# import pandas as pd
# from cowrie_feature_mapper import CowrieToNSLKDDMapper
# from typing import Dict
# from collections import deque

# class CowrieRealTimeReportProcessor:
#     """
#     Real-time Cowrie log processor with live summary report
#     """

#     def __init__(self, ssh_host: str, ssh_user: str, ssh_key_path: str, 
#                  model_dir: str = 'models', report_interval: int = 300):
#         """
#         Args:
#             ssh_host: Remote server IP or hostname
#             ssh_user: SSH user
#             ssh_key_path: Path to private key
#             model_dir: Directory with trained model
#             report_interval: Interval (seconds) to generate live report
#         """
#         self.ssh_host = ssh_host
#         self.ssh_user = ssh_user
#         self.ssh_key_path = ssh_key_path
#         self.remote_cowrie_path = "/var/log/cowrie/cowrie.json"
#         self.report_interval = report_interval

#         self.mapper = CowrieToNSLKDDMapper()
#         self.model_dir = model_dir
#         self.model = None
#         self.scaler = None
#         self.feature_columns = []
#         self.model_info = {}

#         self.log_queue = deque()  # store processed sessions
#         self.lock = threading.Lock()

#         self._load_model()
#         self._setup_ssh()

#     def _load_model(self):
#         import joblib
#         print("\n🤖 Loading ML Model...")
#         try:
#             with open(f"{self.model_dir}/best_model_info.json", 'r') as f:
#                 self.model_info = json.load(f)

#             model_name = self.model_info['name'].replace(' ', '_').lower()
#             self.model = joblib.load(f"{self.model_dir}/{model_name}.pkl")
#             self.scaler = joblib.load(f"{self.model_dir}/scaler.pkl")
#             self.feature_columns = joblib.load(f"{self.model_dir}/feature_columns.pkl")

#             print(f"✓ Loaded: {self.model_info['name']}")
#             print(f"  Accuracy: {self.model_info['metrics']['Accuracy']*100:.2f}%")
#             print(f"  F1-Score: {self.model_info['metrics']['F1-Score']*100:.2f}%")
#         except Exception as e:
#             print(f"❌ Error loading model: {e}")
#             raise

#     def _setup_ssh(self):
#         print(f"\n🔗 Connecting to {self.ssh_host} via SSH...")
#         key = paramiko.RSAKey.from_private_key_file(self.ssh_key_path)
#         self.ssh_client = paramiko.SSHClient()
#         self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         self.ssh_client.connect(hostname=self.ssh_host, username=self.ssh_user, pkey=key)
#         print("✓ SSH connection established")

#     def _predict_batch(self, features_df: pd.DataFrame) -> Dict:
#         X = features_df[self.feature_columns].values
#         X_scaled = self.scaler.transform(X)
#         predictions = self.model.predict(X_scaled)

#         if hasattr(self.model, 'predict_proba'):
#             probabilities = self.model.predict_proba(X_scaled)
#             attack_probs = probabilities[:, 1] if probabilities.shape[1] > 1 else probabilities[:, 0]
#         else:
#             attack_probs = predictions.astype(float) * 0.8

#         attack_types, severities = [], []
#         for idx, row in features_df.iterrows():
#             attack_type = self._classify_attack(row)
#             severity = self._calculate_severity(row, attack_probs[idx])
#             attack_types.append(attack_type)
#             severities.append(severity)

#         return {
#             'prediction': predictions,
#             'attack_probability': attack_probs,
#             'attack_type': attack_types,
#             'severity': severities
#         }

#     def _classify_attack(self, features: pd.Series) -> str:
#         if features.get('num_failed_logins', 0) >= 5:
#             return 'SSH Brute Force'
#         elif features.get('num_compromised', 0) > 0:
#             return 'Command Injection'
#         elif features.get('num_file_creations', 0) > 0:
#             return 'Malware Download'
#         elif features.get('count', 0) > 50:
#             return 'DoS Attack'
#         elif features.get('count', 0) > 10:
#             return 'Port Scan'
#         else:
#             return 'Suspicious Activity'

#     def _calculate_severity(self, features: pd.Series, attack_prob: float) -> str:
#         score = 0
#         if features.get('num_failed_logins', 0) > 10:
#             score += 3
#         if features.get('num_compromised', 0) > 0:
#             score += 4
#         if features.get('root_shell', 0) == 1:
#             score += 4
#         if attack_prob > 0.9:
#             score += 3
#         if score >= 8:
#             return 'Critical'
#         elif score >= 5:
#             return 'High'
#         elif score >= 3:
#             return 'Medium'
#         else:
#             return 'Low'

#     def _generate_live_report(self):
#         """Periodically print a summary report from processed sessions"""
#         while True:
#             time.sleep(self.report_interval)
#             with self.lock:
#                 if not self.log_queue:
#                     print("\n⚠️ No sessions processed yet.")
#                     continue
#                 df = pd.DataFrame(list(self.log_queue))
#             total_sessions = len(df)
#             attacks = (df['prediction'] == 1).sum()
#             attack_rate = (attacks / total_sessions * 100)
#             print(f"\n📊 Live Report ({pd.Timestamp.now()}):")
#             print(f"  Total sessions: {total_sessions}")
#             print(f"  Attacks detected: {attacks} ({attack_rate:.2f}%)")
#             if attacks > 0:
#                 attack_types = df[df['prediction'] == 1]['attack_type'].value_counts()
#                 print("  Attack types:")
#                 for t, c in attack_types.items():
#                     print(f"    {t}: {c}")
#                 severity_counts = df[df['prediction'] == 1]['severity'].value_counts()
#                 print("  Severity distribution:")
#                 for s, c in severity_counts.items():
#                     print(f"    {s}: {c}")
#             print("─" * 50)

#     def tail_cowrie_logs(self):
#         """Stream cowrie.json logs in real-time and process them"""
#         # Start live report thread
#         report_thread = threading.Thread(target=self._generate_live_report, daemon=True)
#         report_thread.start()

#         cmd = f"tail -F {self.remote_cowrie_path}"
#         stdin, stdout, stderr = self.ssh_client.exec_command(cmd)

#         print("\n⏱️ Listening to Cowrie logs in real-time...")
#         for line in stdout:
#             line = line.strip()
#             if not line:
#                 continue
#             try:
#                 log_entry = json.loads(line)
#             except json.JSONDecodeError:
#                 continue  # skip malformed lines

#             features_df = self.mapper.process_cowrie_entry(log_entry)
#             if features_df.empty:
#                 continue

#             predictions = self._predict_batch(features_df)
#             features_df['prediction'] = predictions['prediction']
#             features_df['attack_probability'] = predictions['attack_probability']
#             features_df['attack_type'] = predictions['attack_type']
#             features_df['severity'] = predictions['severity']

#             session_result = features_df.iloc[0].to_dict()
#             with self.lock:
#                 self.log_queue.append(session_result)

#             # Immediate alert for this session
#             print(f"🚨 Session Prediction: {session_result['attack_type']} "
#                   f"(Severity: {session_result['severity']}, "
#                   f"Prob: {session_result['attack_probability']:.2%})")



# processor = CowrieRealTimeReportProcessor(
#     ssh_host="98.94.3.233",
#     ssh_user="ubuntu",
#     ssh_key_path="cowrie_key.pem",
#     report_interval=300  # every 5 minutes
# )
# processor.tail_cowrie_logs()



# import pandas as pd
# import joblib
# import json
# import threading
# import time
# import paramiko
# from datetime import datetime
# from cowrie_feature_mapper import CowrieToNSLKDDMapper

# class CowrieLiveProcessor:
#     def __init__(self, ssh_host, ssh_user, ssh_key, remote_cowrie_path="/var/log/cowrie/cowrie.json", model_dir="models", output_csv="live_results.csv", report_interval=60):
#         self.ssh_host = ssh_host
#         self.ssh_user = ssh_user
#         self.ssh_key = ssh_key
#         self.remote_cowrie_path = remote_cowrie_path
#         self.model_dir = model_dir
#         self.output_csv = output_csv
#         self.report_interval = report_interval

#         self.mapper = CowrieToNSLKDDMapper()
#         self.model = None
#         self.scaler = None
#         self.feature_columns = []
#         self.model_info = {}
        
#         self.log_queue = []  # Stores dicts of processed sessions
#         self.lock = threading.Lock()

#         self._load_model()
#         self._connect_ssh()
#         self._process_existing_logs()

#     def _load_model(self):
#         print("\n🤖 Loading ML Model...")
#         with open(f"{self.model_dir}/best_model_info.json") as f:
#             self.model_info = json.load(f)
#         model_name = self.model_info['name'].replace(' ', '_').lower()
#         self.model = joblib.load(f"{self.model_dir}/{model_name}.pkl")
#         self.scaler = joblib.load(f"{self.model_dir}/scaler.pkl")
#         self.feature_columns = joblib.load(f"{self.model_dir}/feature_columns.pkl")
#         print(f"✓ Loaded: {self.model_info['name']} | Accuracy: {self.model_info['metrics']['Accuracy']*100:.2f}%")

#     def _connect_ssh(self):
#         print(f"\n🔗 Connecting to {self.ssh_host} via SSH...")
#         self.ssh_client = paramiko.SSHClient()
#         self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         self.ssh_client.connect(self.ssh_host, username=self.ssh_user, key_filename=self.ssh_key)
#         print("✓ SSH connection established")

#     def _process_existing_logs(self):
#         print("\n📂 Processing existing Cowrie logs...")
#         cmd = f"cat {self.remote_cowrie_path}"
#         stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
#         for line in stdout:
#             try:
#                 log_entry = json.loads(line)
#                 self._process_entry(log_entry)
#             except json.JSONDecodeError:
#                 continue
#         print("✓ Existing logs processed")

#     def _process_entry(self, log_entry):
#         features_df = self.mapper.process_cowrie_entry(log_entry)
#         if features_df.empty:
#             return
#         predictions = self._predict_batch(features_df)
#         features_df['prediction'] = predictions['prediction']
#         features_df['attack_probability'] = predictions['attack_probability']
#         features_df['attack_type'] = predictions['attack_type']
#         features_df['severity'] = predictions['severity']
#         with self.lock:
#             self.log_queue.append(features_df.iloc[0].to_dict())

#     def _predict_batch(self, features_df):
#         X = features_df[self.feature_columns].values
#         X_scaled = self.scaler.transform(X)
#         predictions = self.model.predict(X_scaled)
#         if hasattr(self.model, 'predict_proba'):
#             probs = self.model.predict_proba(X_scaled)
#             attack_probs = probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]
#         else:
#             attack_probs = predictions.astype(float) * 0.8
#         attack_types, severities = [], []
#         for idx, row in features_df.iterrows():
#             attack_type = self._classify_attack(row)
#             severity = self._calculate_severity(row, attack_probs[idx] if idx < len(attack_probs) else 0.5)
#             attack_types.append(attack_type)
#             severities.append(severity)
#         return {
#             'prediction': predictions,
#             'attack_probability': attack_probs,
#             'attack_type': attack_types,
#             'severity': severities
#         }

#     def _classify_attack(self, features):
#         if features.get('num_failed_logins', 0) >= 5:
#             return 'SSH Brute Force'
#         elif features.get('num_compromised', 0) > 0:
#             return 'Command Injection'
#         elif features.get('num_file_creations', 0) > 0:
#             return 'Malware Download'
#         elif features.get('count', 0) > 50:
#             return 'DoS Attack'
#         elif features.get('count', 0) > 10:
#             return 'Port Scan'
#         else:
#             return 'Suspicious Activity'

#     def _calculate_severity(self, features, attack_prob):
#         score = 0
#         if features.get('num_failed_logins', 0) > 10:
#             score += 3
#         if features.get('num_compromised', 0) > 0:
#             score += 4
#         if features.get('root_shell', 0) == 1:
#             score += 4
#         if attack_prob > 0.9:
#             score += 3
#         if score >= 8:
#             return 'Critical'
#         elif score >= 5:
#             return 'High'
#         elif score >= 3:
#             return 'Medium'
#         return 'Low'

#     def tail_logs(self):
#         print("\n⏱️ Listening to Cowrie logs in real-time...")
#         cmd = f"tail -F {self.remote_cowrie_path}"
#         stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
#         for line in stdout:
#             try:
#                 log_entry = json.loads(line)
#                 self._process_entry(log_entry)
#             except json.JSONDecodeError:
#                 continue

#     def generate_live_report(self):
#         while True:
#             time.sleep(self.report_interval)
#             with self.lock:
#                 if not self.log_queue:
#                     continue
#                 df = pd.DataFrame(self.log_queue)
#                 df.to_csv(self.output_csv, index=False)
#                 attacks = (df['prediction'] == 1).sum()
#                 total = len(df)
#                 print(f"\n📊 Live Report: {total} sessions, {attacks} attacks")
#                 high_conf = df[df['attack_probability'] > 0.9]
#                 if not high_conf.empty:
#                     print(f"⚡ High Confidence Detections: {len(high_conf)} sessions, types: {', '.join(high_conf['attack_type'].unique())}")

#     def start(self):
#         report_thread = threading.Thread(target=self.generate_live_report, daemon=True)
#         report_thread.start()
#         self.tail_logs()  # Blocks and listens indefinitely


# if __name__ == "__main__":
#     processor = CowrieLiveProcessor(
#         ssh_host="98.94.3.233",
#         ssh_user="ubuntu",
#         ssh_key="cowrie_key.pem",
#         remote_cowrie_path="/var/log/cowrie/cowrie.json",
#         report_interval=30  # every 30 seconds
#     )
#     processor.start()


# import paramiko

# # SSH details
# SSH_HOST = "98.94.3.233"
# SSH_USER = "ubuntu"
# SSH_KEY = "cowrie_key.pem"  # path to your private key
# REMOTE_COWRIE_PATH = "/home/ubuntu/cowrie/var/log/cowrie/cowrie.json"
# LOCAL_SAVE_PATH = "cowrie.json"

# def fetch_cowrie_log():
#     print(f"🔗 Connecting to {SSH_HOST} via SSH...")
#     ssh = paramiko.SSHClient()
#     ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     ssh.connect(SSH_HOST, username=SSH_USER, key_filename=SSH_KEY)
#     print("✓ SSH connection established")

#     sftp = ssh.open_sftp()
#     print(f"📂 Downloading {REMOTE_COWRIE_PATH} → {LOCAL_SAVE_PATH} ...")
#     sftp.get(REMOTE_COWRIE_PATH, LOCAL_SAVE_PATH)
#     sftp.close()
#     ssh.close()
#     print(f"✅ Download complete. Saved to {LOCAL_SAVE_PATH}")

# if __name__ == "__main__":
#     fetch_cowrie_log()
