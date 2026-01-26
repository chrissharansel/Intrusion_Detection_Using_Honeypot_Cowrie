"""
ML Classifier Module - Hybrid ML and Rule-Based Classification
Combines machine learning models with expert rules for attack detection
"""

import joblib
import json
import os
import numpy as np
from typing import Dict, Optional


class HybridMLClassifier:
    """Combines pre-trained ML model with honeypot-specific rules"""
    
    def __init__(self, model_dir: str = 'models'):
        """
        Initialize hybrid classifier
        
        Args:
            model_dir: Directory containing trained ML models
        """
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.feature_columns = []
        self.has_ml_model = False
        
        # Rule-based detection thresholds
        self.thresholds = {
            'brute_force_logins': 5,
            'high_command_count': 50,
            'malicious_command_confidence': 0.92,
            'login_frequency_threshold': 0.5  # logins per second
        }
        
        # Try to load pre-trained model
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained ML model if available"""
        try:
            # Check if model files exist
            model_info_path = os.path.join(self.model_dir, 'best_model_info.json')
            
            if not os.path.exists(model_info_path):
                print("⚠ No pre-trained ML model found, using rule-based detection only")
                return
            
            # Load model metadata
            with open(model_info_path, 'r') as f:
                best_model_info = json.load(f)
            
            model_name = best_model_info['name']
            model_filename = os.path.join(
                self.model_dir, 
                f"{model_name.replace(' ', '_').lower()}.pkl"
            )
            
            # Load model components
            self.model = joblib.load(model_filename)
            self.scaler = joblib.load(os.path.join(self.model_dir, 'scaler.pkl'))
            self.feature_columns = joblib.load(os.path.join(self.model_dir, 'feature_columns.pkl'))
            
            self.has_ml_model = True
            print(f"✓ ML model loaded successfully: {model_name}")
            
        except FileNotFoundError as e:
            print(f"⚠ Model file not found: {e}")
            print("⚠ Falling back to rule-based detection")
        except Exception as e:
            print(f"⚠ Error loading ML model: {e}")
            print("⚠ Using rule-based detection only")
    
    def classify(self, features: Dict) -> Dict:
        """
        Classify event using hybrid approach
        
        Args:
            features: Feature dictionary from feature extractor
            
        Returns:
            Classification result with confidence score
        """
        # Rule-based classification (always available)
        rule_result = self._rule_based_classification(features)
        
        # If ML model available and applicable, combine results
        if self.has_ml_model and self._can_use_ml(features):
            try:
                ml_result = self._ml_classification(features)
                
                # Combine both - take higher confidence
                if ml_result['confidence'] > rule_result['confidence']:
                    return {
                        **ml_result,
                        'method': 'hybrid (ML primary)',
                        'rule_confidence': rule_result['confidence']
                    }
                else:
                    return {
                        **rule_result,
                        'ml_confidence': ml_result.get('confidence', 0)
                    }
            except Exception as e:
                print(f"⚠ ML classification error: {e}, using rules")
                return rule_result
        
        return rule_result
    
    def _rule_based_classification(self, features: Dict) -> Dict:
        """
        Rule-based attack classification using expert knowledge
        
        Args:
            features: Feature dictionary
            
        Returns:
            Classification result
        """
        is_attack = False
        confidence = features.get('confidence', 0.5)
        attack_indicators = []
        
        # Check failed login threshold (brute force indicator)
        failed_logins = features.get('failed_logins', 0)
        if failed_logins >= self.thresholds['brute_force_logins']:
            is_attack = True
            confidence = min(0.85 + (failed_logins * 0.02), 0.99)
            attack_indicators.append(f"Failed logins: {failed_logins}")
        
        # Check for malicious commands
        if features.get('has_malicious_commands', 0) == 1:
            is_attack = True
            confidence = max(confidence, self.thresholds['malicious_command_confidence'])
            attack_indicators.append("Malicious commands detected")
        
        # Check command frequency (automated attacks)
        num_commands = features.get('num_commands', 0)
        if num_commands > self.thresholds['high_command_count']:
            is_attack = True
            confidence = max(confidence, 0.80)
            attack_indicators.append(f"High command count: {num_commands}")
        
        # Check login frequency (rapid authentication attempts)
        login_freq = features.get('login_frequency', 0)
        if login_freq > self.thresholds['login_frequency_threshold']:
            is_attack = True
            confidence = max(confidence, 0.88)
            attack_indicators.append(f"High login frequency: {login_freq:.2f}/s")
        
        # Check for credential stuffing (many unique usernames)
        unique_cmds = features.get('unique_commands', 0)
        if unique_cmds > 20:
            is_attack = True
            confidence = max(confidence, 0.75)
            attack_indicators.append(f"Many unique commands: {unique_cmds}")
        
        return {
            'is_attack': is_attack,
            'confidence': confidence,
            'method': 'rule-based',
            'indicators': attack_indicators,
            'attack_type': features.get('attack_type', 'Unknown'),
            'severity': features.get('severity', 'Medium')
        }
    
    def _can_use_ml(self, features: Dict) -> bool:
        """
        Check if we have enough features for ML classification
        
        Args:
            features: Feature dictionary
            
        Returns:
            True if ML can be applied
        """
        # ML model typically needs network flow features
        # For honeypot logs, we primarily use rule-based
        # This can be extended when network flow data is available
        
        required_features = ['session_duration', 'num_commands', 'failed_logins']
        return all(feat in features for feat in required_features)
    
    def _ml_classification(self, features: Dict) -> Dict:
        """
        ML-based classification using trained model
        
        Args:
            features: Feature dictionary
            
        Returns:
            ML classification result
        """
        try:
            # Prepare feature vector
            feature_vector = self._prepare_feature_vector(features)
            
            # Scale features
            scaled_features = self.scaler.transform([feature_vector])
            
            # Predict
            prediction = self.model.predict(scaled_features)[0]
            
            # Get probability if available
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(scaled_features)[0]
                confidence = max(proba)
            else:
                confidence = 0.75  # Default confidence for non-probabilistic models
            
            return {
                'is_attack': bool(prediction),
                'confidence': float(confidence),
                'method': 'ml',
                'attack_type': features.get('attack_type', 'Unknown'),
                'severity': features.get('severity', 'Medium')
            }
            
        except Exception as e:
            print(f"⚠ ML prediction error: {e}")
            # Fallback to rule-based
            return self._rule_based_classification(features)
    
    def _prepare_feature_vector(self, features: Dict) -> list:
        """
        Prepare feature vector for ML model
        
        Args:
            features: Feature dictionary
            
        Returns:
            List of feature values in correct order
        """
        feature_vector = []
        
        for col in self.feature_columns:
            # Map feature names to values
            value = features.get(col, 0)
            
            # Handle categorical features
            if isinstance(value, str):
                value = hash(value) % 1000  # Simple encoding
            
            feature_vector.append(float(value))
        
        return feature_vector
    
    def update_thresholds(self, new_thresholds: Dict):
        """
        Update detection thresholds
        
        Args:
            new_thresholds: Dictionary of threshold updates
        """
        self.thresholds.update(new_thresholds)
        print(f"✓ Updated thresholds: {new_thresholds}")
    
    def get_model_info(self) -> Dict:
        """Get information about loaded models"""
        return {
            'has_ml_model': self.has_ml_model,
            'model_type': type(self.model).__name__ if self.model else None,
            'num_features': len(self.feature_columns) if self.feature_columns else 0,
            'thresholds': self.thresholds
        }


# Example usage
if __name__ == "__main__":
    # Test classifier
    classifier = HybridMLClassifier()
    
    # Test features
    test_features = {
        'failed_logins': 8,
        'has_malicious_commands': 1,
        'num_commands': 15,
        'login_frequency': 0.3,
        'confidence': 0.7,
        'attack_type': 'SSH Brute Force',
        'severity': 'High'
    }
    
    # Classify
    result = classifier.classify(test_features)
    
    print("\nClassification Result:")
    print(f"Is Attack: {result['is_attack']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Method: {result['method']}")
    print(f"Attack Type: {result['attack_type']}")
    print(f"Severity: {result['severity']}")
    
    if result.get('indicators'):
        print(f"Indicators: {', '.join(result['indicators'])}")