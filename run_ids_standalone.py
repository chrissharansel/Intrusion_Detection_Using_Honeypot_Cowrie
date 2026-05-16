from time import time
from typing import Dict
from integrated_ids_engine import IntegratedIDSEngine


# Main execution

def main():
    """Main execution with trained model"""
    
    # Configuration
    COWRIE_HOST = "34.207.216.238"
    COWRIE_USER = "ubuntu"
    COWRIE_KEY = "cowrie-key.pem"
    MODEL_DIR = "models"
    
    # Initialize IDS with trained model
    ids = IntegratedIDSEngine(COWRIE_HOST, COWRIE_USER, COWRIE_KEY, MODEL_DIR)
    
    # Register alert callback
    def print_alert(incident: Dict):
        """Print ML-based alert"""
        print(f"\n🚨 ML ALERT: {incident['attack_type']} from {incident['src_ip']}")
        print(f"   Severity: {incident['severity']}")
        print(f"   Confidence: {incident['confidence']:.2%}")
        print(f"   Attack Probability: {incident['attack_probability']:.2%}")
        print(f"   Model: {incident['model_name']}")
        
        if incident['details'].get('username'):
            print(f"   Username: {incident['details']['username']}")
        
        if incident['details'].get('command'):
            print(f"   Command: {incident['details']['command']}")
        
        # Show key NSL-KDD features
        nsl_features = incident['details'].get('nsl_kdd_features', {})
        if any(nsl_features.values()):
            print(f"   NSL-KDD Indicators:")
            if nsl_features.get('hot', 0) > 0:
                print(f"     - Hot indicators: {nsl_features['hot']}")
            if nsl_features.get('num_compromised', 0) > 0:
                print(f"     - Compromise indicators: {nsl_features['num_compromised']}")
            if nsl_features.get('root_shell', 0) == 1:
                print(f"     - Root shell detected!")
    
    ids.register_alert_callback(print_alert)
    
    # Start IDS
    if ids.start():
        print("\nPress Ctrl+C to stop monitoring\n")
        
        try:
            while True:
                time.sleep(30)
                stats = ids.get_stats()
                print(f"\n📊 Live Stats:")
                print(f"   Events: {stats['total_events']} | "
                      f"Attacks: {stats['attacks_detected']} | "
                      f"IPs: {stats['unique_attackers']} | "
                      f"Rate: {stats['attack_rate']}%")
                print(f"   Model: {stats['model_info']['name']} | "
                      f"Avg Confidence: {stats['avg_confidence']:.2%}")
                
        except KeyboardInterrupt:
            print("\n\nReceived interrupt signal...")
            ids.stop()
    else:
        print("\n❌ Failed to start IDS")


if __name__ == "__main__":
    main()