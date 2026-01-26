"""
Cowrie to NSL-KDD Feature Mapper
Maps Cowrie honeypot logs to NSL-KDD dataset features for ML model prediction
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict
from typing import Dict, List


class CowrieToNSLKDDMapper:
    """
    Maps Cowrie honeypot events to NSL-KDD feature format
    Enables trained NSL-KDD models to work with Cowrie data
    """
    
    def __init__(self):
        """Initialize the mapper with session tracking"""
        self.sessions = defaultdict(lambda: {
            'start_time': None,
            'end_time': None,
            'protocol': 'tcp',
            'service': 'ssh',
            'commands': [],
            'login_attempts': [],
            'src_bytes': 0,
            'dst_bytes': 0,
            'events': [],
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'files_created': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'connections': 0
        })
        
        # NSL-KDD feature template with defaults
        self.nsl_kdd_features = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 
            'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds',
            'is_host_login', 'is_guest_login', 'count', 'srv_count',
            'serror_rate', 'srv_serror_rate', 'rerror_rate', 
            'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]
        
        # Malicious command patterns
        self.malicious_patterns = [
            'wget', 'curl', 'nc', 'netcat', 'bash', '/bin/sh', 'chmod',
            'python', 'perl', 'ruby', 'php', 'rm -rf', 'dd if=',
            'cat /etc/passwd', 'cat /etc/shadow', 'uname -a', 'whoami',
            '/bin/busybox', 'tftp', 'echo', '>', '>>', 'sh -i', 'bash -i',
            'nohup', '&', '|', 'chroot', 'iptables', 'service', 'systemctl'
        ]
        
        # Connection tracking for network features
        self.connection_history = defaultdict(list)
        self.ip_connections = defaultdict(lambda: defaultdict(int))
        
    def process_cowrie_event(self, event: Dict) -> Dict:
        """
        Process a single Cowrie event and update session data
        
        Args:
            event: Cowrie JSON log event
            
        Returns:
            NSL-KDD formatted feature dictionary
        """
        session_id = event.get('session', 'unknown')
        session = self.sessions[session_id]
        
        # Initialize session if first event
        if session['start_time'] is None:
            session['start_time'] = event.get('timestamp')
            session['src_ip'] = event.get('src_ip', '0.0.0.0')
            session['dst_ip'] = event.get('dst_ip', '0.0.0.0')
            session['src_port'] = event.get('src_port', 0)
            session['dst_port'] = event.get('dst_port', 22)
        
        # Update end time
        session['end_time'] = event.get('timestamp')
        session['events'].append(event)
        
        # Process event based on type
        event_id = event.get('eventid', '')
        
        if event_id == 'cowrie.login.failed':
            session['failed_logins'] += 1
            session['login_attempts'].append({
                'username': event.get('username'),
                'password': event.get('password'),
                'success': False
            })
            
        elif event_id == 'cowrie.login.success':
            session['successful_logins'] += 1
            session['logged_in'] = 1
            session['login_attempts'].append({
                'username': event.get('username'),
                'password': event.get('password'),
                'success': True
            })
            
        elif event_id == 'cowrie.command.input':
            command = event.get('input', '')
            session['commands'].append(command)
            
        elif event_id == 'cowrie.session.file_download':
            session['dst_bytes'] += event.get('size', 0)
            session['files_created'] += 1
            
        elif event_id == 'cowrie.session.file_upload':
            session['src_bytes'] += event.get('size', 0)
            session['files_created'] += 1
            
        elif event_id == 'cowrie.session.connect':
            session['connections'] += 1
            
        elif event_id == 'cowrie.client.size':
            # Terminal size event indicates interactive session
            pass
        
        # Update connection tracking
        self._update_connection_tracking(session_id, session)
        
        # Generate NSL-KDD features for this session
        features = self._generate_nsl_kdd_features(session_id, session)
        
        return features
    
    def _update_connection_tracking(self, session_id: str, session: Dict):
        """Update connection history for network-based features"""
        src_ip = session['src_ip']
        dst_ip = session['dst_ip']
        service = session['service']
        
        # Track this connection
        self.connection_history[src_ip].append({
            'session': session_id,
            'service': service,
            'timestamp': session['end_time']
        })
        
        # Keep only last 100 connections per IP
        if len(self.connection_history[src_ip]) > 100:
            self.connection_history[src_ip] = self.connection_history[src_ip][-100:]
        
        # Track service counts
        self.ip_connections[src_ip][service] += 1
    
    def _generate_nsl_kdd_features(self, session_id: str, session: Dict) -> Dict:
        """
        Generate NSL-KDD compatible features from Cowrie session
        
        Args:
            session_id: Session identifier
            session: Session data dictionary
            
        Returns:
            Dictionary with all NSL-KDD features
        """
        features = {}
        
        # Basic features
        features['duration'] = self._calculate_duration(session)
        features['protocol_type'] = 0  # tcp (encoded)
        features['service'] = 11  # ssh (encoded as index)
        features['flag'] = 11  # SF (normal connection)
        features['src_bytes'] = session['src_bytes']
        features['dst_bytes'] = session['dst_bytes']
        
        # TCP/IP features
        features['land'] = 1 if session['src_ip'] == session['dst_ip'] else 0
        features['wrong_fragment'] = 0  # Not available in Cowrie
        features['urgent'] = 0  # Not available in Cowrie
        
        # Content features
        features['hot'] = self._count_hot_indicators(session)
        features['num_failed_logins'] = session['failed_logins']
        features['logged_in'] = 1 if session['successful_logins'] > 0 else 0
        features['num_compromised'] = self._detect_compromise_indicators(session)
        features['root_shell'] = self._detect_root_shell(session)
        features['su_attempted'] = self._detect_su_attempt(session)
        features['num_root'] = self._count_root_access(session)
        features['num_file_creations'] = session['files_created']
        features['num_shells'] = self._count_shell_spawns(session)
        features['num_access_files'] = self._count_file_access(session)
        features['num_outbound_cmds'] = self._count_outbound_commands(session)
        
        # Guest/host features
        features['is_host_login'] = 0
        features['is_guest_login'] = self._is_guest_login(session)
        
        # Time-based traffic features (past 2 seconds)
        src_ip = session['src_ip']
        recent_connections = self._get_recent_connections(src_ip, 2)
        
        features['count'] = len(recent_connections)
        features['srv_count'] = sum(1 for c in recent_connections if c['service'] == session['service'])
        
        # Connection error rates
        features['serror_rate'] = 0  # Simplified
        features['srv_serror_rate'] = 0  # Simplified
        features['rerror_rate'] = 0  # Simplified
        features['srv_rerror_rate'] = 0  # Simplified
        
        # Service-based features
        if features['count'] > 0:
            features['same_srv_rate'] = features['srv_count'] / features['count']
            features['diff_srv_rate'] = 1 - features['same_srv_rate']
        else:
            features['same_srv_rate'] = 0
            features['diff_srv_rate'] = 0
        
        # Host-based traffic features (past 100 connections)
        all_connections = self.connection_history[src_ip][-100:]
        
        features['srv_diff_host_rate'] = 0  # Simplified for honeypot
        features['dst_host_count'] = len(all_connections)
        features['dst_host_srv_count'] = sum(1 for c in all_connections if c['service'] == session['service'])
        
        if features['dst_host_count'] > 0:
            features['dst_host_same_srv_rate'] = features['dst_host_srv_count'] / features['dst_host_count']
            features['dst_host_diff_srv_rate'] = 1 - features['dst_host_same_srv_rate']
        else:
            features['dst_host_same_srv_rate'] = 0
            features['dst_host_diff_srv_rate'] = 0
        
        features['dst_host_same_src_port_rate'] = 1.0  # Most honeypot traffic uses same port
        features['dst_host_srv_diff_host_rate'] = 0  # Honeypot typically has one host
        
        # Error rates (simplified)
        features['dst_host_serror_rate'] = 0
        features['dst_host_srv_serror_rate'] = 0
        features['dst_host_rerror_rate'] = 0
        features['dst_host_srv_rerror_rate'] = 0
        
        return features
    
    def _calculate_duration(self, session: Dict) -> float:
        """Calculate session duration in seconds"""
        if not session['start_time'] or not session['end_time']:
            return 0
        
        try:
            start = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
            end = datetime.fromisoformat(session['end_time'].replace('Z', '+00:00'))
            return max(0, (end - start).total_seconds())
        except:
            return 0
    
    def _count_hot_indicators(self, session: Dict) -> int:
        """Count 'hot' indicators (suspicious activities)"""
        hot_count = 0
        
        for cmd in session['commands']:
            cmd_lower = cmd.lower()
            # Root access attempts
            if any(p in cmd_lower for p in ['sudo', 'su ', 'passwd']):
                hot_count += 1
            # File modifications
            if any(p in cmd_lower for p in ['chmod', 'chown', 'chgrp']):
                hot_count += 1
            # Network commands
            if any(p in cmd_lower for p in ['wget', 'curl', 'nc', 'netcat']):
                hot_count += 1
        
        return min(hot_count, 10)  # Cap at 10
    
    def _detect_compromise_indicators(self, session: Dict) -> int:
        """Detect compromise indicators"""
        compromise_count = 0
        
        for cmd in session['commands']:
            cmd_lower = cmd.lower()
            if any(pattern in cmd_lower for pattern in self.malicious_patterns):
                compromise_count += 1
        
        # Successful login after many failures
        if session['failed_logins'] > 5 and session['successful_logins'] > 0:
            compromise_count += 5
        
        # Many commands executed
        if len(session['commands']) > 20:
            compromise_count += 3
        
        return min(compromise_count, 100)
    
    def _detect_root_shell(self, session: Dict) -> int:
        """Detect root shell access"""
        for cmd in session['commands']:
            if any(p in cmd.lower() for p in ['sudo sh', 'sudo bash', 'su -', 'su root']):
                return 1
        return 0
    
    def _detect_su_attempt(self, session: Dict) -> int:
        """Detect su command attempts"""
        for cmd in session['commands']:
            if cmd.lower().startswith('su ') or cmd.lower() == 'su':
                return 1
        return 0
    
    def _count_root_access(self, session: Dict) -> int:
        """Count root-level access operations"""
        root_count = 0
        
        for cmd in session['commands']:
            cmd_lower = cmd.lower()
            if cmd_lower.startswith('sudo ') or 'root' in cmd_lower:
                root_count += 1
        
        return root_count
    
    def _count_shell_spawns(self, session: Dict) -> int:
        """Count shell spawn attempts"""
        shell_count = 0
        
        for cmd in session['commands']:
            cmd_lower = cmd.lower()
            if any(s in cmd_lower for s in ['sh', 'bash', 'zsh', '/bin/']):
                shell_count += 1
        
        return shell_count
    
    def _count_file_access(self, session: Dict) -> int:
        """Count file access operations"""
        access_count = 0
        
        for cmd in session['commands']:
            cmd_lower = cmd.lower()
            if any(f in cmd_lower for f in ['cat', 'less', 'more', 'tail', 'head', 'grep']):
                access_count += 1
        
        return access_count
    
    def _count_outbound_commands(self, session: Dict) -> int:
        """Count outbound connection commands"""
        outbound_count = 0
        
        for cmd in session['commands']:
            cmd_lower = cmd.lower()
            if any(o in cmd_lower for o in ['wget', 'curl', 'nc', 'telnet', 'ftp', 'ssh']):
                outbound_count += 1
        
        return outbound_count
    
    def _is_guest_login(self, session: Dict) -> int:
        """Check if guest login was used"""
        for attempt in session['login_attempts']:
            username = attempt.get('username', '').lower()
            if username in ['guest', 'anonymous', 'ftp']:
                return 1
        return 0
    
    def _get_recent_connections(self, src_ip: str, time_window: int) -> List[Dict]:
        """Get connections from src_ip within time_window seconds"""
        # Simplified - return all recent connections
        return self.connection_history[src_ip][-10:]
    
    def process_cowrie_log_file(self, log_file_path: str) -> pd.DataFrame:
        """
        Process an entire Cowrie JSON log file
        
        Args:
            log_file_path: Path to cowrie.json file
            
        Returns:
            DataFrame with NSL-KDD formatted features for each session
        """
        print(f"\n{'='*70}")
        print(f"📁 Processing Cowrie Log File: {log_file_path}")
        print(f"{'='*70}")
        
        events = []
        session_features = {}
        
        try:
            with open(log_file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        event = json.loads(line.strip())
                        events.append(event)
                        
                        # Process event and get features
                        features = self.process_cowrie_event(event)
                        session_id = event.get('session', 'unknown')
                        
                        # Store features for this session
                        session_features[session_id] = features
                        
                        if line_num % 1000 == 0:
                            print(f"  Processed {line_num:,} events...")
                            
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        print(f"  ⚠ Error on line {line_num}: {e}")
                        continue
            
            print(f"\n✓ Processed {len(events):,} events")
            print(f"✓ Generated features for {len(session_features):,} sessions")
            
            # Convert to DataFrame
            df = pd.DataFrame.from_dict(session_features, orient='index')
            
            # Ensure all NSL-KDD features are present
            for feature in self.nsl_kdd_features:
                if feature not in df.columns:
                    df[feature] = 0
            
            # Reorder columns to match NSL-KDD
            df = df[self.nsl_kdd_features]
            
            print(f"✓ DataFrame shape: {df.shape}")
            print(f"\n📊 Feature Summary:")
            print(f"  Total sessions: {len(df):,}")
            print(f"  Sessions with logins: {(df['logged_in'] == 1).sum():,}")
            print(f"  Sessions with failed logins: {(df['num_failed_logins'] > 0).sum():,}")
            print(f"  Average duration: {df['duration'].mean():.2f}s")
            
            return df
            
        except FileNotFoundError:
            print(f"❌ Log file not found: {log_file_path}")
            return pd.DataFrame()
        except Exception as e:
            print(f"❌ Error processing log file: {e}")
            return pd.DataFrame()
    
    def get_session_summary(self, session_id: str) -> Dict:
        """Get detailed summary for a specific session"""
        return self.sessions.get(session_id, {})
    
    def clear_old_sessions(self, max_age_seconds: int = 3600):
        """Clear session data older than max_age_seconds"""
        current_time = datetime.now()
        sessions_to_remove = []
        
        for session_id, session_data in self.sessions.items():
            if session_data['end_time']:
                try:
                    end_time = datetime.fromisoformat(
                        session_data['end_time'].replace('Z', '+00:00')
                    )
                    age = (current_time - end_time).total_seconds()
                    if age > max_age_seconds:
                        sessions_to_remove.append(session_id)
                except:
                    pass
        
        for session_id in sessions_to_remove:
            del self.sessions[session_id]
        
        if sessions_to_remove:
            print(f"✓ Cleared {len(sessions_to_remove)} old sessions")


# Example usage
if __name__ == "__main__":
    # Create mapper
    mapper = CowrieToNSLKDDMapper()
    
    # Process Cowrie log file
    cowrie_log_path = "cowrie.json"  # Your Cowrie log file
    
    # Generate NSL-KDD features
    features_df = mapper.process_cowrie_log_file(cowrie_log_path)
    
    if not features_df.empty:
        # Save features
        output_file = "cowrie_nsl_kdd_features.csv"
        features_df.to_csv(output_file, index=False)
        print(f"\n✓ Features saved to: {output_file}")
        
        # Display sample
        print(f"\n📋 Sample Features (first 5 rows):")
        print(features_df.head())
        
        print(f"\n📊 Feature Statistics:")
        print(features_df.describe())