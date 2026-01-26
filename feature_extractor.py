"""
Feature Extractor Module - Convert Cowrie Logs to ML Features
Extracts behavioral and statistical features from honeypot events
"""

from datetime import datetime
from collections import defaultdict
from typing import Dict, List


class CowrieFeatureExtractor:
    """Extract ML features from Cowrie honeypot events"""
    
    def __init__(self):
        """Initialize feature extractor with session tracking"""
        self.session_data = defaultdict(lambda: {
            'commands': [],
            'login_attempts': [],
            'bytes_sent': 0,
            'bytes_received': 0,
            'start_time': None,
            'end_time': None,
            'events': [],
            'src_ip': None,
            'protocol': None
        })
        
        # Attack pattern signatures
        self.brute_force_threshold = 5
        self.port_scan_threshold = 10
        self.command_injection_patterns = [
            'wget', 'curl', 'nc', 'bash', '/bin/sh', 'chmod', 
            'python', 'perl', 'ruby', 'php', 'rm -rf',
            'dd if=', 'cat /etc/passwd', 'uname -a'
        ]
        
    def process_event(self, event: Dict) -> Dict:
        """
        Process a single Cowrie event and extract features
        
        Args:
            event: Cowrie log event dictionary
            
        Returns:
            Dictionary of extracted features
        """
        event_id = event.get('eventid', '')
        session = event.get('session', 'unknown')
        
        # Initialize session if first event
        if self.session_data[session]['start_time'] is None:
            self.session_data[session]['start_time'] = event.get('timestamp')
            self.session_data[session]['src_ip'] = event.get('src_ip')
        
        # Update end time
        self.session_data[session]['end_time'] = event.get('timestamp')
        
        # Store event
        self.session_data[session]['events'].append(event)
        
        # Process specific event types
        self._process_event_type(event, session, event_id)
        
        # Extract and return features
        return self.extract_features_from_event(event)
    
    def _process_event_type(self, event: Dict, session: str, event_id: str):
        """Process different types of Cowrie events"""
        
        if event_id == 'cowrie.login.failed':
            self.session_data[session]['login_attempts'].append({
                'username': event.get('username'),
                'password': event.get('password'),
                'timestamp': event.get('timestamp'),
                'success': False
            })
            
        elif event_id == 'cowrie.login.success':
            self.session_data[session]['login_attempts'].append({
                'username': event.get('username'),
                'password': event.get('password'),
                'timestamp': event.get('timestamp'),
                'success': True
            })
            
        elif event_id == 'cowrie.command.input':
            command = event.get('input', '')
            self.session_data[session]['commands'].append(command)
            
        elif event_id == 'cowrie.session.file_download':
            # Track file downloads (malware, scripts)
            self.session_data[session]['bytes_received'] += event.get('size', 0)
            
        elif event_id == 'cowrie.client.size':
            # Terminal size - indicates interactive session
            pass
    
    def extract_features_from_event(self, event: Dict) -> Dict:
        """
        Extract ML-compatible features from event
        
        Args:
            event: Cowrie event dictionary
            
        Returns:
            Feature dictionary for ML classification
        """
        session = event.get('session', 'unknown')
        session_info = self.session_data[session]
        
        features = {
            # Basic identifiers
            'src_ip': event.get('src_ip', '0.0.0.0'),
            'timestamp': event.get('timestamp', ''),
            'eventid': event.get('eventid', ''),
            'session': session,
            
            # Session-based features
            'session_duration': self._calculate_duration(session),
            'num_commands': len(session_info['commands']),
            'num_login_attempts': len(session_info['login_attempts']),
            'failed_logins': self._count_failed_logins(session_info),
            'successful_logins': self._count_successful_logins(session_info),
            
            # Behavioral features
            'has_malicious_commands': int(self._check_malicious_commands(session_info['commands'])),
            'login_frequency': self._calculate_login_frequency(session_info['login_attempts']),
            'command_frequency': self._calculate_command_frequency(session_info),
            'unique_commands': len(set(session_info['commands'])),
            
            # Data transfer features
            'bytes_transferred': session_info['bytes_sent'] + session_info['bytes_received'],
            
            # Attack classification
            'attack_type': self._classify_attack_type(session_info, event),
            'severity': self._calculate_severity(session_info),
            'confidence': self._calculate_confidence(session_info)
        }
        
        return features
    
    def _calculate_duration(self, session: str) -> float:
        """Calculate session duration in seconds"""
        session_info = self.session_data[session]
        
        if not session_info['start_time'] or not session_info['end_time']:
            return 0
        
        try:
            start = datetime.fromisoformat(session_info['start_time'].replace('Z', '+00:00'))
            end = datetime.fromisoformat(session_info['end_time'].replace('Z', '+00:00'))
            return (end - start).total_seconds()
        except:
            return 0
    
    def _count_failed_logins(self, session_info: Dict) -> int:
        """Count failed login attempts"""
        return sum(1 for l in session_info['login_attempts'] 
                   if not l.get('success', False))
    
    def _count_successful_logins(self, session_info: Dict) -> int:
        """Count successful login attempts"""
        return sum(1 for l in session_info['login_attempts'] 
                   if l.get('success', False))
    
    def _check_malicious_commands(self, commands: List[str]) -> bool:
        """Check for malicious command patterns"""
        for cmd in commands:
            cmd_lower = cmd.lower()
            for pattern in self.command_injection_patterns:
                if pattern in cmd_lower:
                    return True
        return False
    
    def _calculate_login_frequency(self, login_attempts: List[Dict]) -> float:
        """Calculate login attempt frequency (attempts per second)"""
        if len(login_attempts) < 2:
            return 0
        
        try:
            times = [datetime.fromisoformat(l['timestamp'].replace('Z', '+00:00')) 
                    for l in login_attempts]
            time_diffs = [(times[i+1] - times[i]).total_seconds() 
                         for i in range(len(times)-1)]
            total_time = sum(time_diffs)
            return len(login_attempts) / max(total_time, 1)
        except:
            return 0
    
    def _calculate_command_frequency(self, session_info: Dict) -> float:
        """Calculate command execution frequency"""
        duration = self._calculate_duration(session_info.get('session', ''))
        if duration > 0:
            return len(session_info['commands']) / duration
        return 0
    
    def _classify_attack_type(self, session_info: Dict, event: Dict) -> str:
        """Classify the type of attack based on behavior"""
        
        # SSH Brute Force - multiple failed login attempts
        if session_info['failed_logins'] >= self.brute_force_threshold:
            return 'SSH Brute Force'
        
        # Command Injection - malicious commands detected
        if self._check_malicious_commands(session_info['commands']):
            return 'Command Injection'
        
        # Port Scan - many connection attempts, no commands
        if (len(session_info['events']) > self.port_scan_threshold and 
            session_info['num_commands'] == 0):
            return 'Port Scan'
        
        # Credential Stuffing - many unique usernames
        unique_usernames = len(set([l.get('username') for l in session_info['login_attempts']]))
        if unique_usernames > 10:
            return 'Credential Stuffing'
        
        # Malware Download
        if session_info['bytes_received'] > 10000:
            return 'Malware Download'
        
        # Failed Authentication
        if session_info['failed_logins'] > 0:
            return 'Failed Authentication'
        
        # Default - Reconnaissance
        return 'Reconnaissance'
    
    def _calculate_severity(self, session_info: Dict) -> str:
        """
        Calculate attack severity based on indicators
        
        Returns:
            Severity level: Critical, High, Medium, Low
        """
        severity_score = 0
        
        # Failed logins
        if session_info['failed_logins'] > 10:
            severity_score += 3
        elif session_info['failed_logins'] > 5:
            severity_score += 2
        elif session_info['failed_logins'] > 0:
            severity_score += 1
        
        # Malicious commands
        if self._check_malicious_commands(session_info['commands']):
            severity_score += 3
        
        # Many commands (potential automation)
        if session_info['num_commands'] > 20:
            severity_score += 2
        elif session_info['num_commands'] > 50:
            severity_score += 3
        
        # Large data transfer (potential exfiltration)
        if session_info['bytes_transferred'] > 100000:
            severity_score += 2
        
        # Map score to severity level
        if severity_score >= 6:
            return 'Critical'
        elif severity_score >= 4:
            return 'High'
        elif severity_score >= 2:
            return 'Medium'
        else:
            return 'Low'
    
    def _calculate_confidence(self, session_info: Dict) -> float:
        """
        Calculate detection confidence score
        
        Returns:
            Confidence score between 0 and 1
        """
        confidence = 0.5
        
        # More evidence = higher confidence
        if session_info['num_commands'] > 0:
            confidence += 0.1
        if session_info['failed_logins'] > 0:
            confidence += 0.15
        if len(session_info['events']) > 10:
            confidence += 0.1
        if self._check_malicious_commands(session_info['commands']):
            confidence += 0.2
        if session_info['failed_logins'] > 5:
            confidence += 0.1
        
        return min(confidence, 0.99)
    
    def get_session_summary(self, session: str) -> Dict:
        """Get complete summary of a session"""
        return self.session_data.get(session, {})
    
    def clear_old_sessions(self, max_age_seconds: int = 3600):
        """Clear session data older than max_age_seconds"""
        current_time = datetime.now()
        sessions_to_remove = []
        
        for session, data in self.session_data.items():
            if data['end_time']:
                try:
                    end_time = datetime.fromisoformat(data['end_time'].replace('Z', '+00:00'))
                    age = (current_time - end_time).total_seconds()
                    if age > max_age_seconds:
                        sessions_to_remove.append(session)
                except:
                    pass
        
        for session in sessions_to_remove:
            del self.session_data[session]
        
        if sessions_to_remove:
            print(f"✓ Cleared {len(sessions_to_remove)} old sessions")