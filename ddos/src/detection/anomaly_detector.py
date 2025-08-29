import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import SVC, OneClassSVM
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.metrics import roc_auc_score, precision_recall_curve
import joblib
import logging
import os
from typing import Dict, List, Tuple, Optional
import yaml

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Anomaly detection class for DoS/DDoS attack detection
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = self._load_config(config_path)
        self.models = {}
        self.model_dir = "models"
        self.preprocessor = None  # Will be set when data is preprocessed

        # Create models directory if it doesn't exist
        if not os.path.exists(self.model_dir):
            os.makedirs(self.model_dir)

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file"""
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)

    def create_models(self) -> Dict:
        """
        Create and return dictionary of anomaly detection models
        """
        models = {}

        # Random Forest Classifier
        rf_config = self.config['models']['random_forest']
        models['random_forest'] = RandomForestClassifier(
            n_estimators=rf_config['n_estimators'],
            max_depth=rf_config['max_depth'],
            random_state=rf_config['random_state']
        )

        # Support Vector Machine
        svm_config = self.config['models']['svm']
        models['svm'] = SVC(
            kernel=svm_config['kernel'],
            C=svm_config['C'],
            gamma=svm_config['gamma'],
            probability=True,
            random_state=42
        )

        # Isolation Forest (unsupervised)
        if_config = self.config['models']['isolation_forest']
        models['isolation_forest'] = IsolationForest(
            n_estimators=if_config['n_estimators'],
            contamination=if_config['contamination'],
            random_state=if_config['random_state']
        )

        # One-Class SVM (unsupervised)
        models['one_class_svm'] = OneClassSVM(
            kernel='rbf',
            nu=0.1,
            gamma='scale'
        )

        logger.info(f"Created {len(models)} models: {list(models.keys())}")
        return models

    def train_model(self, model_name: str, X_train: np.ndarray, y_train: np.ndarray) -> dict:
        """
        Train a specific model and return training results
        """
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found. Create models first.")

        logger.info(f"Training {model_name} model")

        model = self.models[model_name]

        # Train the model
        model.fit(X_train, y_train)

        # Get training predictions
        if hasattr(model, 'predict_proba'):
            y_pred_proba = model.predict_proba(X_train)
            y_pred = model.predict(X_train)
        else:
            y_pred = model.predict(X_train)
            y_pred_proba = None

        # Calculate training metrics
        results = {
            'model_name': model_name,
            'training_accuracy': accuracy_score(y_train, y_pred) if y_pred_proba is not None else None,
            'feature_importance': getattr(model, 'feature_importances_', None)
        }

        logger.info(f"{model_name} training completed. Accuracy: {results['training_accuracy']}")

        return results

    def evaluate_model(self, model_name: str, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        """
        Evaluate a trained model on test data
        """
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found.")

        model = self.models[model_name]

        # Get predictions
        if hasattr(model, 'predict_proba'):
            y_pred_proba = model.predict_proba(X_test)
            y_pred = model.predict(X_test)
        else:
            y_pred = model.predict(X_test)
            y_pred_proba = None

        # Calculate metrics
        results = {
            'model_name': model_name,
            'accuracy': accuracy_score(y_test, y_pred) if y_pred_proba is not None else None,
            'classification_report': classification_report(y_test, y_pred, output_dict=True) if y_pred_proba is not None else None,
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist() if y_pred_proba is not None else None,
        }

        # Add AUC score if probabilities are available
        if y_pred_proba is not None and y_pred_proba.shape[1] > 1:
            results['auc_score'] = roc_auc_score(y_test, y_pred_proba[:, 1])

        logger.info(f"{model_name} evaluation - Accuracy: {results['accuracy']}")

        return results

    def predict_anomaly(self, model_name: str, X: np.ndarray,
                       threshold: Optional[float] = None) -> Tuple[np.ndarray, np.ndarray]:
        """
        Make predictions using a trained model
        Returns: (predictions, probabilities/confidence_scores)
        """
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found.")

        model = self.models[model_name]

        # Ensure X is properly formatted
        if isinstance(X, pd.DataFrame):
            X = X.values

        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(X)
            predictions = model.predict(X)

            if threshold is not None:
                # Apply custom threshold
                predictions = (probabilities[:, 1] >= threshold).astype(int)

            return predictions, probabilities[:, 1]

        elif hasattr(model, 'decision_function'):
            # For models like One-Class SVM
            scores = model.decision_function(X)
            predictions = model.predict(X)
            return predictions, scores

        else:
            predictions = model.predict(X)
            return predictions, np.zeros(len(X))

    def save_model(self, model_name: str, filepath: Optional[str] = None) -> str:
        """
        Save a trained model to disk
        """
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found.")

        if filepath is None:
            filepath = os.path.join(self.model_dir, f"{model_name}.pkl")

        joblib.dump(self.models[model_name], filepath)
        logger.info(f"Model {model_name} saved to {filepath}")

        return filepath

    def load_model(self, model_name: str, filepath: Optional[str] = None) -> bool:
        """
        Load a trained model from disk
        """
        if filepath is None:
            filepath = os.path.join(self.model_dir, f"{model_name}.pkl")

        if not os.path.exists(filepath):
            logger.error(f"Model file {filepath} not found")
            return False

        self.models[model_name] = joblib.load(filepath)
        logger.info(f"Model {model_name} loaded from {filepath}")

        return True

    def get_model_feature_importance(self, model_name: str) -> Optional[np.ndarray]:
        """
        Get feature importance for tree-based models
        """
        if model_name not in self.models:
            return None

        model = self.models[model_name]
        return getattr(model, 'feature_importances_', None)

    def detect_dos_attack(self, X: np.ndarray, model_name: str = 'random_forest',
                         threshold: Optional[float] = None) -> Dict:
        """
        Detect DoS attacks in network traffic data
        """
        if threshold is None:
            threshold = self.config['detection']['dos_threshold']

        predictions, scores = self.predict_anomaly(model_name, X, threshold)

        # Calculate attack statistics
        attack_count = np.sum(predictions == 1)  # Assuming 1 = attack
        total_samples = len(predictions)
        attack_percentage = (attack_count / total_samples) * 100

        results = {
            'total_samples': total_samples,
            'attack_count': int(attack_count),
            'attack_percentage': float(attack_percentage),
            'is_under_attack': attack_percentage > threshold * 100,
            'predictions': predictions.tolist(),
            'scores': scores.tolist(),
            'threshold': threshold
        }

        return results

    def get_attack_summary(self, results: Dict) -> str:
        """
        Generate a human-readable summary of attack detection results
        """
        summary = f"""
DoS Attack Detection Summary:
-----------------------------
Total Samples Analyzed: {results['total_samples']}
Detected Attacks: {results['attack_count']} ({results['attack_percentage']:.2f}%)
Threshold: {results['threshold']:.2f}
Status: {'UNDER ATTACK' if results['is_under_attack'] else 'NORMAL TRAFFIC'}
        """

        return summary.strip()

    def preprocess_new_data(self, data: pd.DataFrame) -> np.ndarray:
        """
        Preprocess new data using the fitted preprocessor
        """
        if self.preprocessor is None:
            raise ValueError("Preprocessor not set. Train models first.")

        logger.info(f"Preprocessing new data with shape: {data.shape}")

        # Detect column types and preprocess
        column_types = self.preprocessor._detect_column_types(data)

        # Preprocess each column based on its type
        X_processed = data.copy()
        for col in data.columns:
            if col in column_types:
                col_type = column_types[col]
                try:
                    X_processed[col] = self.preprocessor._preprocess_column(data[col], col_type)
                except Exception as e:
                    logger.warning(f"Error preprocessing column '{col}': {e}. Using numeric conversion as fallback.")
                    X_processed[col] = pd.to_numeric(data[col], errors='coerce').fillna(0)

        # Convert to numeric and handle any remaining issues
        X_processed = X_processed.apply(pd.to_numeric, errors='coerce').fillna(0)

        # Scale features using fitted scaler
        X_processed = self.preprocessor.scaler.transform(X_processed)

        return X_processed