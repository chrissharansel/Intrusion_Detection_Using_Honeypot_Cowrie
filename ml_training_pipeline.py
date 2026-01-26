"""
Complete Machine Learning Training Pipeline for IDS
Supports NSL-KDD and UNSW-NB15 datasets with multiple ML models
Generates models ready for honeypot integration
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                             f1_score, confusion_matrix, classification_report,
                             roc_curve, auc, roc_auc_score)
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
import joblib
import warnings
import time
from datetime import datetime
import json
import os

warnings.filterwarnings('ignore')


class IDSMLPipeline:
    """Complete ML pipeline for Intrusion Detection System"""
    
    def __init__(self, dataset_type='nsl-kdd'):
        """
        Initialize the IDS ML Pipeline
        
        Args:
            dataset_type: 'nsl-kdd' or 'unsw-nb15'
        """
        self.dataset_type = dataset_type
        self.models = {}
        self.results = {}
        self.best_model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_columns = []
        
        # Define models
        self.model_dict = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100, 
                random_state=42, 
                n_jobs=-1,
                max_depth=20
            ),
            'Decision Tree': DecisionTreeClassifier(
                random_state=42,
                max_depth=15
            ),
            'K-Nearest Neighbors': KNeighborsClassifier(
                n_neighbors=5, 
                n_jobs=-1
            ),
            'Logistic Regression': LogisticRegression(
                max_iter=1000, 
                random_state=42, 
                n_jobs=-1
            ),
            'XGBoost': XGBClassifier(
                random_state=42, 
                n_jobs=-1, 
                eval_metric='logloss',
                max_depth=10,
                learning_rate=0.1
            ),
            'LightGBM': LGBMClassifier(
                random_state=42, 
                n_jobs=-1, 
                verbose=-1,
                max_depth=10
            )
        }
        
        print(f"\n{'='*70}")
        print(f"🤖 IDS ML Pipeline Initialized")
        print(f"{'='*70}")
        print(f"Dataset: {dataset_type.upper()}")
        print(f"Models: {len(self.model_dict)}")
        print(f"{'='*70}\n")
    
    def load_nsl_kdd(self, train_path='data/KDDTrain+.txt', test_path='data/KDDTest+.txt'):
        """Load and preprocess NSL-KDD dataset"""
        print("\n" + "="*70)
        print("📂 LOADING NSL-KDD DATASET")
        print("="*70)
        
        # Column names for NSL-KDD
        columns = [
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
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
            'label', 'difficulty'
        ]
        
        try:
            print(f"Loading training data from: {train_path}")
            train_df = pd.read_csv(train_path, names=columns)
            print(f"✓ Training set loaded: {train_df.shape}")
            
            print(f"Loading test data from: {test_path}")
            test_df = pd.read_csv(test_path, names=columns)
            print(f"✓ Test set loaded: {test_df.shape}")
            
            # Combine for preprocessing
            df = pd.concat([train_df, test_df], ignore_index=True)
            print(f"✓ Combined dataset: {df.shape}")
            
            # Convert to binary classification (normal vs attack)
            df['attack'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)
            
            print(f"\n📊 Class Distribution:")
            print(f"  Normal: {(df['attack']==0).sum():,} ({(df['attack']==0).sum()/len(df)*100:.2f}%)")
            print(f"  Attack: {(df['attack']==1).sum():,} ({(df['attack']==1).sum()/len(df)*100:.2f}%)")
            
            # Show attack types
            print(f"\n🎯 Attack Types in Dataset:")
            attack_types = df[df['label'] != 'normal']['label'].value_counts().head(10)
            for attack, count in attack_types.items():
                print(f"  {attack}: {count:,}")
            
            return df, train_df.shape[0]
            
        except FileNotFoundError as e:
            print("\n❌ Dataset files not found!")
            print("\n📥 Please download NSL-KDD dataset:")
            print("  1. Training: https://github.com/defcom17/NSL_KDD/raw/master/KDDTrain%2B.txt")
            print("  2. Testing: https://github.com/defcom17/NSL_KDD/raw/master/KDDTest%2B.txt")
            print(f"\n💡 Create 'data/' directory and place files there")
            return None, 0
    
    def load_unsw_nb15(self, file_path='data/UNSW-NB15.csv'):
        """Load and preprocess UNSW-NB15 dataset"""
        print("\n" + "="*70)
        print("📂 LOADING UNSW-NB15 DATASET")
        print("="*70)
        
        try:
            df = pd.read_csv(file_path)
            print(f"✓ Dataset loaded: {df.shape}")
            
            # The label column is typically named 'label' or 'attack_cat'
            if 'label' in df.columns:
                df['attack'] = df['label']
            elif 'attack_cat' in df.columns:
                df['attack'] = df['attack_cat'].apply(lambda x: 0 if x == 'Normal' else 1)
            
            print(f"\n📊 Class Distribution:")
            print(df['attack'].value_counts())
            
            # Calculate split point (70-30)
            split_point = int(len(df) * 0.7)
            
            return df, split_point
            
        except FileNotFoundError:
            print("\n❌ Dataset file not found!")
            print("📥 Please download UNSW-NB15 dataset from:")
            print("https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/")
            return None, 0
    
    def preprocess_data(self, df, split_point):
        """Preprocess the dataset"""
        print("\n" + "="*70)
        print("⚙️  PREPROCESSING DATA")
        print("="*70)
        
        # Remove label and difficulty columns from features
        exclude_cols = ['label', 'difficulty', 'attack', 'attack_cat', 'id', 'Unnamed: 0']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        
        X = df[feature_cols].copy()
        y = df['attack'].copy()
        
        print(f"Features: {len(feature_cols)}")
        print(f"Samples: {len(X):,}")
        
        # Handle categorical variables
        categorical_cols = X.select_dtypes(include=['object']).columns
        print(f"\n🏷️  Encoding {len(categorical_cols)} categorical columns...")
        
        for col in categorical_cols:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
            self.label_encoders[col] = le
            print(f"  ✓ {col}: {len(le.classes_)} unique values")
        
        # Handle missing values
        missing_count = X.isnull().sum().sum()
        if missing_count > 0:
            print(f"\n🔧 Handling {missing_count:,} missing values...")
            X = X.fillna(X.median())
        
        # Split into train and test
        X_train = X.iloc[:split_point]
        X_test = X.iloc[split_point:]
        y_train = y.iloc[:split_point]
        y_test = y.iloc[split_point:]
        
        print(f"\n📊 Dataset Split:")
        print(f"  Training set: {X_train.shape}")
        print(f"  Test set: {X_test.shape}")
        print(f"  Train attack rate: {(y_train.sum()/len(y_train)*100):.2f}%")
        print(f"  Test attack rate: {(y_test.sum()/len(y_test)*100):.2f}%")
        
        # Scale features
        print("\n⚖️  Scaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Convert back to DataFrame
        X_train_scaled = pd.DataFrame(X_train_scaled, columns=feature_cols)
        X_test_scaled = pd.DataFrame(X_test_scaled, columns=feature_cols)
        
        self.feature_columns = feature_cols
        
        print("✓ Preprocessing complete")
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def train_models(self, X_train, y_train):
        """Train all models"""
        print("\n" + "="*70)
        print("🎓 TRAINING MODELS")
        print("="*70)
        
        for name, model in self.model_dict.items():
            print(f"\n{'─'*70}")
            print(f"🔄 Training {name}...")
            print(f"{'─'*70}")
            start_time = time.time()
            
            try:
                model.fit(X_train, y_train)
                training_time = time.time() - start_time
                
                self.models[name] = {
                    'model': model,
                    'training_time': training_time
                }
                
                print(f"✓ {name} trained successfully")
                print(f"⏱️  Training time: {training_time:.2f} seconds")
                
            except Exception as e:
                print(f"❌ Error training {name}: {str(e)}")
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate all trained models"""
        print("\n" + "="*70)
        print("📊 EVALUATING MODELS")
        print("="*70)
        
        results = []
        
        for name, model_info in self.models.items():
            print(f"\n{'─'*70}")
            print(f"📈 Evaluating {name}...")
            print(f"{'─'*70}")
            model = model_info['model']
            
            # Predictions
            start_time = time.time()
            y_pred = model.predict(X_test)
            prediction_time = time.time() - start_time
            
            # Metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            # ROC AUC (if probability predictions available)
            try:
                y_proba = model.predict_proba(X_test)[:, 1]
                roc_auc = roc_auc_score(y_test, y_proba)
            except:
                roc_auc = 0.0
            
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            
            # False Positive Rate
            fpr = cm[0][1] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0
            
            result = {
                'Model': name,
                'Accuracy': accuracy,
                'Precision': precision,
                'Recall': recall,
                'F1-Score': f1,
                'ROC-AUC': roc_auc,
                'FPR': fpr,
                'Training Time (s)': model_info['training_time'],
                'Prediction Time (s)': prediction_time,
                'Confusion Matrix': cm
            }
            
            results.append(result)
            self.results[name] = result
            
            # Print metrics
            print(f"✓ Accuracy:  {accuracy*100:.2f}%")
            print(f"✓ Precision: {precision*100:.2f}%")
            print(f"✓ Recall:    {recall*100:.2f}%")
            print(f"✓ F1-Score:  {f1*100:.2f}%")
            if roc_auc > 0:
                print(f"✓ ROC-AUC:   {roc_auc:.4f}")
            print(f"✓ FPR:       {fpr*100:.2f}%")
        
        # Create results DataFrame
        results_df = pd.DataFrame(results)
        results_df = results_df.sort_values('F1-Score', ascending=False)
        
        print("\n" + "="*70)
        print("🏆 OVERALL RESULTS (Ranked by F1-Score)")
        print("="*70)
        display_cols = ['Model', 'Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC', 'FPR']
        print(results_df[display_cols].to_string(index=False))
        
        # Identify best model
        best_model_name = results_df.iloc[0]['Model']
        self.best_model = {
            'name': best_model_name,
            'model': self.models[best_model_name]['model'],
            'metrics': self.results[best_model_name]
        }
        
        print(f"\n{'='*70}")
        print(f"🏆 BEST MODEL: {best_model_name}")
        print(f"{'='*70}")
        print(f"F1-Score: {self.results[best_model_name]['F1-Score']*100:.2f}%")
        print(f"Accuracy: {self.results[best_model_name]['Accuracy']*100:.2f}%")
        print(f"{'='*70}")
        
        return results_df
    
    def save_models(self, output_dir='models'):
        """Save all trained models and preprocessors"""
        print("\n" + "="*70)
        print("💾 SAVING MODELS")
        print("="*70)
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Save each model
        for name, model_info in self.models.items():
            model_filename = f"{output_dir}/{name.replace(' ', '_').lower()}.pkl"
            joblib.dump(model_info['model'], model_filename)
            print(f"✓ Saved {name}")
            print(f"  → {model_filename}")
        
        # Save scaler
        scaler_filename = f"{output_dir}/scaler.pkl"
        joblib.dump(self.scaler, scaler_filename)
        print(f"✓ Saved StandardScaler")
        print(f"  → {scaler_filename}")
        
        # Save label encoders
        encoders_filename = f"{output_dir}/label_encoders.pkl"
        joblib.dump(self.label_encoders, encoders_filename)
        print(f"✓ Saved Label Encoders ({len(self.label_encoders)} encoders)")
        print(f"  → {encoders_filename}")
        
        # Save feature columns
        features_filename = f"{output_dir}/feature_columns.pkl"
        joblib.dump(self.feature_columns, features_filename)
        print(f"✓ Saved Feature Columns ({len(self.feature_columns)} features)")
        print(f"  → {features_filename}")
        
        # Save best model info
        best_model_info = {
            'name': self.best_model['name'],
            'dataset': self.dataset_type,
            'num_features': len(self.feature_columns),
            'metrics': {
                k: float(v) if isinstance(v, (np.floating, np.integer)) else str(v)
                for k, v in self.best_model['metrics'].items() 
                if k != 'Confusion Matrix'
            },
            'confusion_matrix': {
                'TN': int(self.best_model['metrics']['Confusion Matrix'][0][0]),
                'FP': int(self.best_model['metrics']['Confusion Matrix'][0][1]),
                'FN': int(self.best_model['metrics']['Confusion Matrix'][1][0]),
                'TP': int(self.best_model['metrics']['Confusion Matrix'][1][1])
            },
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'feature_columns': self.feature_columns
        }
        
        with open(f"{output_dir}/best_model_info.json", 'w') as f:
            json.dump(best_model_info, f, indent=2)
        print(f"✓ Saved Best Model Metadata")
        print(f"  → {output_dir}/best_model_info.json")
        
        print(f"\n{'='*70}")
        print(f"✅ All models saved to '{output_dir}/' directory")
        print(f"{'='*70}")
    
    # def save_models(self, output_dir='models'):
    #     """Save all trained models and preprocessors (DEPLOYMENT SAFE)"""
    #     print("\n" + "="*70)
    #     print("💾 SAVING MODELS (DEPLOYMENT SAFE)")
    #     print("="*70)

    #     os.makedirs(output_dir, exist_ok=True)

    #     for name, model_info in self.models.items():
    #         model = model_info['model']
    #         safe_name = name.replace(' ', '_').lower()

    #         # 🔥 FIX: XGBoost must NOT be pickled
    #         if name == 'XGBoost':
    #             model.save_model(f"{output_dir}/xgboost.json")
    #             print(f"✓ Saved XGBoost model → {output_dir}/xgboost.json")
    #         else:
    #             joblib.dump(model, f"{output_dir}/{safe_name}.pkl")
    #             print(f"✓ Saved {name} → {output_dir}/{safe_name}.pkl")

    #     # Save scaler
    #     joblib.dump(self.scaler, f"{output_dir}/scaler.pkl")
    #     print("✓ Saved scaler.pkl")

    #     # Save encoders
    #     joblib.dump(self.label_encoders, f"{output_dir}/label_encoders.pkl")
    #     print("✓ Saved label_encoders.pkl")

    #     # Save feature columns
    #     joblib.dump(self.feature_columns, f"{output_dir}/feature_columns.pkl")
    #     print("✓ Saved feature_columns.pkl")

    #     # Save metadata
    #     with open(f"{output_dir}/best_model_info.json", "w") as f:
    #         json.dump({
    #             "name": self.best_model['name'],
    #             "dataset": self.dataset_type,
    #             "num_features": len(self.feature_columns),
    #             "metrics": {
    #                 k: float(v)
    #                 for k, v in self.best_model['metrics'].items()
    #                 if isinstance(v, (int, float, np.integer, np.floating))
    #             }

    #         }, f, indent=2)

    #     print("\n✅ ALL MODELS SAVED CORRECTLY")

    def predict_new_data(self, new_data):
        """
        Predict on new preprocessed data
        
        Args:
            new_data: DataFrame with same features as training data
            
        Returns:
            predictions: Array of predictions (0=normal, 1=attack)
            probabilities: Array of attack probabilities
        """
        if self.best_model is None:
            raise Exception("No model trained yet!")
        
        # Ensure correct column order
        X_new = new_data[self.feature_columns].copy()
        
        model = self.best_model['model']
        
        # Make predictions
        predictions = model.predict(X_new)
        
        # Get probabilities if available
        try:
            probabilities = model.predict_proba(X_new)[:, 1]
        except:
            probabilities = predictions.astype(float)
        
        return predictions, probabilities
    
    def visualize_results(self, results_df):
        """Create visualizations of model performance"""
        print("\n" + "="*70)
        print("📊 GENERATING VISUALIZATIONS")
        print("="*70)
        
        # Set style
        sns.set_style("whitegrid")
        plt.rcParams['figure.facecolor'] = 'white'
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('IDS Model Performance Comparison', fontsize=18, fontweight='bold', y=0.995)
        
        # 1. Metrics comparison
        ax1 = axes[0, 0]
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        x = np.arange(len(results_df))
        width = 0.2
        colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12']
        
        for i, (metric, color) in enumerate(zip(metrics, colors)):
            ax1.bar(x + i*width, results_df[metric], width, label=metric, color=color, alpha=0.8)
        
        ax1.set_xlabel('Models', fontsize=11, fontweight='bold')
        ax1.set_ylabel('Score', fontsize=11, fontweight='bold')
        ax1.set_title('Performance Metrics Comparison', fontsize=13, fontweight='bold')
        ax1.set_xticks(x + width * 1.5)
        ax1.set_xticklabels(results_df['Model'], rotation=30, ha='right')
        ax1.legend(loc='lower right')
        ax1.grid(axis='y', alpha=0.3)
        ax1.set_ylim([0, 1.05])
        
        # 2. Training time comparison
        ax2 = axes[0, 1]
        colors_time = plt.cm.viridis(np.linspace(0.3, 0.9, len(results_df)))
        bars = ax2.barh(results_df['Model'], results_df['Training Time (s)'], color=colors_time)
        ax2.set_xlabel('Training Time (seconds)', fontsize=11, fontweight='bold')
        ax2.set_title('Training Time Comparison', fontsize=13, fontweight='bold')
        ax2.grid(axis='x', alpha=0.3)
        
        # Add value labels
        for bar in bars:
            width = bar.get_width()
            ax2.text(width, bar.get_y() + bar.get_height()/2, 
                    f'{width:.2f}s', ha='left', va='center', fontsize=9)
        
        # 3. F1-Score ranking
        ax3 = axes[1, 0]
        colors_f1 = plt.cm.RdYlGn(np.linspace(0.3, 0.9, len(results_df)))
        bars = ax3.barh(results_df['Model'], results_df['F1-Score'], color=colors_f1)
        ax3.set_xlabel('F1-Score', fontsize=11, fontweight='bold')
        ax3.set_title('F1-Score Ranking', fontsize=13, fontweight='bold')
        ax3.grid(axis='x', alpha=0.3)
        ax3.set_xlim([0, 1.05])
        
        # Add value labels
        for bar in bars:
            width = bar.get_width()
            ax3.text(width, bar.get_y() + bar.get_height()/2, 
                    f'{width:.4f}', ha='left', va='center', fontsize=9)
        
        # 4. Confusion matrix for best model
        ax4 = axes[1, 1]
        best_cm = self.results[self.best_model['name']]['Confusion Matrix']
        sns.heatmap(best_cm, annot=True, fmt='d', cmap='Blues', ax=ax4, 
                   cbar_kws={'label': 'Count'}, annot_kws={'size': 12})
        ax4.set_title(f'Confusion Matrix - {self.best_model["name"]}', 
                     fontsize=13, fontweight='bold')
        ax4.set_ylabel('True Label', fontsize=11, fontweight='bold')
        ax4.set_xlabel('Predicted Label', fontsize=11, fontweight='bold')
        ax4.set_xticklabels(['Normal', 'Attack'])
        ax4.set_yticklabels(['Normal', 'Attack'])
        
        plt.tight_layout()
        
        # Save figure
        output_file = 'model_performance.png'
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"✓ Visualization saved: {output_file}")
        plt.close()
        
        # Create additional ROC curve plot if available
        self._plot_roc_curves(results_df)
    
    def _plot_roc_curves(self, results_df):
        """Plot ROC curves for models that support it"""
        models_with_roc = results_df[results_df['ROC-AUC'] > 0]
        
        if len(models_with_roc) > 0:
            print("✓ Generating ROC curves...")
            # This would require storing predictions during evaluation
            # Simplified version for now
    
    def generate_report(self, results_df):
        """Generate a detailed report"""
        print("\n" + "="*70)
        print("📄 GENERATING DETAILED REPORT")
        print("="*70)
        
        report = []
        report.append("="*80)
        report.append("        INTRUSION DETECTION SYSTEM - ML MODEL EVALUATION REPORT")
        report.append("="*80)
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Dataset: {self.dataset_type.upper()}")
        report.append(f"Number of Features: {len(self.feature_columns)}")
        report.append(f"Number of Models Trained: {len(self.models)}")
        
        report.append(f"\n{'-'*80}")
        report.append("MODEL PERFORMANCE SUMMARY")
        report.append("-"*80)
        display_cols = ['Model', 'Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC', 'FPR']
        report.append(results_df[display_cols].to_string(index=False))
        
        report.append(f"\n{'-'*80}")
        report.append("BEST MODEL DETAILS")
        report.append("-"*80)
        report.append(f"Model: {self.best_model['name']}")
        report.append(f"Accuracy:  {self.best_model['metrics']['Accuracy']*100:.2f}%")
        report.append(f"Precision: {self.best_model['metrics']['Precision']*100:.2f}%")
        report.append(f"Recall:    {self.best_model['metrics']['Recall']*100:.2f}%")
        report.append(f"F1-Score:  {self.best_model['metrics']['F1-Score']*100:.2f}%")
        
        if self.best_model['metrics']['ROC-AUC'] > 0:
            report.append(f"ROC-AUC:   {self.best_model['metrics']['ROC-AUC']:.4f}")
        
        cm = self.best_model['metrics']['Confusion Matrix']
        report.append(f"\nConfusion Matrix:")
        report.append(f"  True Negatives (TN):  {cm[0][0]:>8,}")
        report.append(f"  False Positives (FP): {cm[0][1]:>8,}")
        report.append(f"  False Negatives (FN): {cm[1][0]:>8,}")
        report.append(f"  True Positives (TP):  {cm[1][1]:>8,}")
        
        # Calculate additional metrics
        fpr = cm[0][1] / (cm[0][0] + cm[0][1])
        fnr = cm[1][0] / (cm[1][0] + cm[1][1])
        
        report.append(f"\nDetection Metrics:")
        report.append(f"  False Positive Rate: {fpr*100:.2f}%")
        report.append(f"  False Negative Rate: {fnr*100:.2f}%")
        report.append(f"  Detection Rate (TPR): {self.best_model['metrics']['Recall']*100:.2f}%")
        
        report.append(f"\n{'-'*80}")
        report.append("HONEYPOT INTEGRATION RECOMMENDATIONS")
        report.append("-"*80)
        report.append(f"1. Deploy Model: Use '{self.best_model['name']}' for real-time detection")
        report.append(f"2. Detection Threshold: Set at 0.75-0.85 for balanced accuracy")
        report.append(f"3. Expected Performance:")
        report.append(f"   - Detection Rate: {self.best_model['metrics']['Recall']*100:.1f}% of attacks will be detected")
        report.append(f"   - False Alarms: {fpr*100:.2f}% of normal traffic flagged as attacks")
        report.append(f"4. Model Loading: Use models/best_model_info.json for configuration")
        report.append(f"5. Feature Requirements: Ensure all {len(self.feature_columns)} features are extracted")
        
        report.append(f"\n{'-'*80}")
        report.append("DEPLOYMENT CHECKLIST")
        report.append("-"*80)
        report.append("[ ] Load trained model from models/ directory")
        report.append("[ ] Load scaler.pkl for feature normalization")
        report.append("[ ] Load label_encoders.pkl for categorical features")
        report.append("[ ] Verify feature_columns.pkl matches input data")
        report.append("[ ] Set up alert thresholds based on FPR tolerance")
        report.append("[ ] Monitor model performance on live data")
        report.append("[ ] Plan for model retraining with honeypot data")
        
        report.append("\n" + "="*80)
        report.append("END OF REPORT")
        report.append("="*80)

        report_text = '\n'.join(report)

        # Save to file
        report_filename = 'ids_evaluation_report.txt'
        with open(report_filename, 'w') as f:
            f.write(report_text)

        print(report_text)
        print(f"\n✓ Report saved: {report_filename}")





def main():
    # =========================
    # 1️⃣ Initialize Pipeline
    # =========================
    dataset_type = 'nsl-kdd'  # options: 'nsl-kdd' or 'unsw-nb15'
    pipeline = IDSMLPipeline(dataset_type=dataset_type)
    
    # =========================
    # 2️⃣ Load Dataset
    # =========================
    if dataset_type.lower() == 'nsl-kdd':
        df, split_point = pipeline.load_nsl_kdd(
            train_path='data/KDDTrain+.txt',
            test_path='data/KDDTest+.txt'
        )
    else:
        df, split_point = pipeline.load_unsw_nb15(file_path='data/UNSW-NB15.csv')
    
    if df is None or split_point == 0:
        print("❌ Dataset not loaded. Exiting...")
        return
    
    # =========================
    # 3️⃣ Preprocess Data
    # =========================
    X_train, X_test, y_train, y_test = pipeline.preprocess_data(df, split_point)
    
    # =========================
    # 4️⃣ Train Models
    # =========================
    pipeline.train_models(X_train, y_train)
    
    # =========================
    # 5️⃣ Evaluate Models
    # =========================
    results_df = pipeline.evaluate_models(X_test, y_test)
    
    # =========================
    # 6️⃣ Save Models & Artifacts
    # =========================
    pipeline.save_models(output_dir='models')
    
    # =========================
    # 7️⃣ Visualize Results
    # =========================
    pipeline.visualize_results(results_df)
    
    # =========================
    # 8️⃣ Generate Report
    # =========================
    pipeline.generate_report(results_df)
    
    print("\n✅ Pipeline completed successfully!")

if __name__ == "__main__":
    main()
