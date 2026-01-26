# """
# Cowrie Monitor Module - SSH Honeypot Log Monitoring
# Handles real-time and historical log retrieval from Cowrie honeypot
# """

# import paramiko
# import json
# import time
# import threading
# from typing import Callable, List, Dict, Optional


# class CowrieMonitor:
#     """Monitor Cowrie honeypot logs from AWS via SSH"""
    
#     def __init__(self, host: str, username: str, key_file: str, 
#                  log_path: str = '/home/ubuntu/cowrie/var/log/cowrie/cowrie.json'):
#         """
#         Initialize Cowrie Monitor
        
#         Args:
#             host: Cowrie server hostname/IP
#             username: SSH username
#             key_file: Path to SSH private key
#             log_path: Path to Cowrie log file on server
#         """
#         self.host = host
#         self.username = username
#         self.key_file = key_file
#         self.log_path = log_path
#         self.ssh_client = None
#         self.running = False
#         self.event_callback = None
#         self.monitor_thread = None
        
#     def connect(self) -> bool:
#         """
#         Establish SSH connection to Cowrie instance
        
#         Returns:
#             bool: True if connection successful, False otherwise
#         """
#         try:
#             self.ssh_client = paramiko.SSHClient()
#             self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
#             # Load private key
#             key = paramiko.RSAKey.from_private_key_file(self.key_file)
            
#             # Connect to server
#             self.ssh_client.connect(
#                 hostname=self.host,
#                 username=self.username,
#                 pkey=key,
#                 timeout=10,
#                 banner_timeout=10
#             )
            
#             print(f"✓ Connected to Cowrie honeypot at {self.host}")
#             return True
            
#         except FileNotFoundError:
#             print(f"❌ SSH key file not found: {self.key_file}")
#             return False
#         except paramiko.AuthenticationException:
#             print(f"❌ Authentication failed - check SSH key")
#             return False
#         except Exception as e:
#             print(f"❌ Connection failed: {e}")
#             return False
    
#     def disconnect(self):
#         """Close SSH connection"""
#         if self.ssh_client:
#             self.ssh_client.close()
#             print("✓ Disconnected from Cowrie honeypot")
    
#     def tail_logs(self, callback: Callable[[Dict], None]):
#         """
#         Monitor logs in real-time using tail -f
        
#         Args:
#             callback: Function to call for each new log event
#         """
#         self.event_callback = callback
#         self.running = True
        
#         try:
#             # Start tailing the log file
#             stdin, stdout, stderr = self.ssh_client.exec_command(
#                 f"tail -f -n 0 {self.log_path}",
#                 get_pty=True
#             )
            
#             print(f"✓ Monitoring Cowrie logs at {self.log_path}")
            
#             while self.running:
#                 # Read line with timeout
#                 line = stdout.readline()
                
#                 if line:
#                     try:
#                         # Parse JSON log entry
#                         event = json.loads(line.strip())
                        
#                         # Call callback with event
#                         if self.event_callback:
#                             self.event_callback(event)
                            
#                     except json.JSONDecodeError:
#                         # Skip malformed JSON
#                         continue
#                     except Exception as e:
#                         print(f"⚠ Error processing event: {e}")
#                 else:
#                     # No data, sleep briefly
#                     time.sleep(0.1)
                    
#         except Exception as e:
#             print(f"❌ Error monitoring logs: {e}")
#             self.running = False
    
#     def start_monitoring(self, callback: Callable[[Dict], None]):
#         """
#         Start monitoring in background thread
        
#         Args:
#             callback: Function to call for each new log event
#         """
#         if self.monitor_thread and self.monitor_thread.is_alive():
#             print("⚠ Monitoring already running")
#             return
        
#         self.monitor_thread = threading.Thread(
#             target=self.tail_logs,
#             args=(callback,),
#             daemon=True
#         )
#         self.monitor_thread.start()
    
#     def get_historical_logs(self, num_lines: int = 1000) -> List[Dict]:
#         """
#         Retrieve historical log entries
        
#         Args:
#             num_lines: Number of recent lines to retrieve
            
#         Returns:
#             List of parsed log events
#         """
#         try:
#             stdin, stdout, stderr = self.ssh_client.exec_command(
#                 f"tail -n {num_lines} {self.log_path}"
#             )
            
#             events = []
#             for line in stdout:
#                 try:
#                     event = json.loads(line.strip())
#                     events.append(event)
#                 except:
#                     continue
            
#             print(f"✓ Retrieved {len(events)} historical log entries")
#             return events
            
#         except Exception as e:
#             print(f"❌ Error retrieving historical logs: {e}")
#             return []
    
#     def test_connection(self) -> bool:
#         """
#         Test if connection is alive
        
#         Returns:
#             bool: True if connection is active
#         """
#         if not self.ssh_client:
#             return False
        
#         try:
#             stdin, stdout, stderr = self.ssh_client.exec_command('echo test')
#             return True
#         except:
#             return False
    
#     def stop(self):
#         """Stop monitoring"""
#         self.running = False
#         if self.monitor_thread:
#             self.monitor_thread.join(timeout=2)


# # Example usage
# if __name__ == "__main__":
#     # Configuration
#     COWRIE_HOST = "98.94.3.233"
#     COWRIE_USER = "ubuntu"
#     COWRIE_KEY = "cowrie_key.pem"
    
#     # Create monitor
#     monitor = CowrieMonitor(COWRIE_HOST, COWRIE_USER, COWRIE_KEY)
    
#     # Define callback
#     def on_event(event):
#         print(f"Event: {event.get('eventid')} from {event.get('src_ip')}")
    
#     # Connect and monitor
#     if monitor.connect():
#         # Get historical data
#         historical = monitor.get_historical_logs(100)
#         print(f"Historical events: {len(historical)}")
        
#         # Start real-time monitoring
#         monitor.start_monitoring(on_event)
        
#         try:
#             while True:
#                 time.sleep(1)
#         except KeyboardInterrupt:
#             print("\nStopping...")
#             monitor.stop()
#             monitor.disconnect()

"""
Cowrie Monitor Module - SSH Honeypot Log Monitoring
✔ Real-time monitoring
✔ Historical log retrieval
✔ Local persistent storage for ML training (JSONL)
"""

import paramiko
import json
import time
import threading
import os
from typing import Callable, List, Dict
from datetime import datetime


# =========================
# LOCAL STORAGE CONFIG
# =========================
LOCAL_LOG_DIR = "ids_data/raw_logs"
LOCAL_LOG_FILE = os.path.join(LOCAL_LOG_DIR, "cowrie_raw.jsonl")

os.makedirs(LOCAL_LOG_DIR, exist_ok=True)


class CowrieMonitor:
    """Monitor Cowrie honeypot logs from remote server via SSH"""

    def __init__(
        self,
        host: str,
        username: str,
        key_file: str,
        log_path: str = "/home/ubuntu/cowrie/var/log/cowrie/cowrie.json",
    ):
        self.host = host
        self.username = username
        self.key_file = key_file
        self.log_path = log_path

        self.ssh_client = None
        self.running = False
        self.event_callback = None
        self.monitor_thread = None

    # =========================
    # SSH CONNECTION
    # =========================
    def connect(self) -> bool:
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            key = paramiko.RSAKey.from_private_key_file(self.key_file)

            self.ssh_client.connect(
                hostname=self.host,
                username=self.username,
                pkey=key,
                timeout=10,
                banner_timeout=10,
            )

            print(f"✓ Connected to Cowrie honeypot at {self.host}")
            return True

        except Exception as e:
            print(f"❌ Cowrie SSH connection failed: {e}")
            return False

    def disconnect(self):
        if self.ssh_client:
            self.ssh_client.close()
            print("✓ Disconnected from Cowrie honeypot")

    # =========================
    # LOCAL PERSISTENCE (NEW)
    # =========================
    def save_raw_event_locally(self, event: Dict):
        """
        Persist raw Cowrie event locally (append-only, ML-friendly)
        """
        try:
            event["_ingested_at"] = datetime.utcnow().isoformat()

            with open(LOCAL_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")

        except Exception as e:
            print(f"⚠ Failed to save local Cowrie log: {e}")

    # =========================
    # REAL-TIME MONITORING
    # =========================
    def tail_logs(self, callback: Callable[[Dict], None]):
        self.event_callback = callback
        self.running = True

        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(
                f"tail -f -n 0 {self.log_path}",
                get_pty=True,
            )

            print(f"✓ Monitoring Cowrie logs at {self.log_path}")

            while self.running:
                line = stdout.readline()

                if not line:
                    time.sleep(0.1)
                    continue

                try:
                    event = json.loads(line.strip())

                    # ✅ NEW: Persist locally
                    self.save_raw_event_locally(event)

                    # Existing behavior (IDS engine)
                    if self.event_callback:
                        self.event_callback(event)

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"⚠ Error processing Cowrie event: {e}")

        except Exception as e:
            print(f"❌ Error monitoring Cowrie logs: {e}")
            self.running = False

    def start_monitoring(self, callback: Callable[[Dict], None]):
        if self.monitor_thread and self.monitor_thread.is_alive():
            print("⚠ Cowrie monitoring already running")
            return

        self.monitor_thread = threading.Thread(
            target=self.tail_logs,
            args=(callback,),
            daemon=True,
        )
        self.monitor_thread.start()

    # =========================
    # HISTORICAL LOG FETCH
    # =========================
    def get_historical_logs(self, num_lines: int = 1000) -> List[Dict]:
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(
                f"tail -n {num_lines} {self.log_path}"
            )

            events = []
            for line in stdout:
                try:
                    event = json.loads(line.strip())
                    events.append(event)

                    # ✅ Also persist historical logs locally
                    self.save_raw_event_locally(event)

                except:
                    continue

            print(f"✓ Retrieved {len(events)} historical Cowrie logs")
            return events

        except Exception as e:
            print(f"❌ Error retrieving historical logs: {e}")
            return []

    # =========================
    # CONTROL
    # =========================
    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)

    def test_connection(self) -> bool:
        if not self.ssh_client:
            return False
        try:
            self.ssh_client.exec_command("echo test")
            return True
        except:
            return False


# =========================
# STANDALONE TEST
# =========================
if __name__ == "__main__":
    COWRIE_HOST = "98.94.3.233"
    COWRIE_USER = "ubuntu"
    COWRIE_KEY = "cowrie_key.pem"

    monitor = CowrieMonitor(COWRIE_HOST, COWRIE_USER, COWRIE_KEY)

    def on_event(event):
        print(f"[LIVE] {event.get('eventid')} from {event.get('src_ip')}")

    if monitor.connect():
        monitor.get_historical_logs(100)
        monitor.start_monitoring(on_event)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop()
            monitor.disconnect()
