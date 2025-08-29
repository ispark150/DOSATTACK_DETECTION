#!/usr/bin/env python3
"""
DoS Attack Detection System - Main Application
==============================================

This is the main entry point for the DoS Attack Detection System.
It provides both command-line interface and programmatic access to
all system components including data preprocessing, model training,
real-time detection, and dashboard visualization.

Usage:
    python main.py --help
    python main.py --train
    python main.py --dashboard
    python main.py --detect --input-file data/sample_traffic.csv
"""

import argparse
import sys
import logging
import pandas as pd
import numpy as np
from pathlib import Path
import yaml
import time
from typing import Optional, Dict, List

# Import system modules
from src.preprocessing.data_preprocessor import DataPreprocessor
from src.detection.anomaly_detector import AnomalyDetector
from src.detection.detection_utils import RealTimeMonitor, AttackClassifier, AlertSystem

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dos_detection.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class DoSDetectionSystem:
    """
    Main DoS Detection System class that orchestrates all components
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize the DoS detection system

        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.preprocessor = DataPreprocessor()
        self.detector = AnomalyDetector(config_path)
        self.monitor = RealTimeMonitor(
            window_size=100,
            threshold=self.config['detection']['dos_threshold']
        )
        self.classifier = AttackClassifier()
        self.alert_system = AlertSystem(
            alert_threshold=self.config['detection']['dos_threshold']
        )

        # System state
        self.data_loaded = False
        self.models_trained = False
        self.monitoring_active = False

        logger.info("DoS Detection System initialized")

    def _load_config(self, config_path: str) -> dict:
        """Load system configuration"""
        try:
            with open(config_path, 'r') as file:
                config = yaml.safe_load(file)
            logger.info(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            # Return default configuration
            return {
                'data': {'use_simulated': True, 'simulated_samples': 10000},
                'detection': {'dos_threshold': 0.7}
            }

    def load_data(self, data_path: Optional[str] = None) -> bool:
        """
        Load and preprocess training data

        Args:
            data_path: Path to CSV file (optional, uses simulated data if not provided)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info("Loading data...")

            if data_path and Path(data_path).exists():
                # Load real data
                df = self.preprocessor.load_cicids_data(data_path)
            else:
                # Generate simulated data
                logger.info("Using simulated data for demonstration")
                df = self.preprocessor.generate_simulated_dos_data(
                    n_samples=self.config['data']['simulated_samples']
                )

            if df is None or df.empty:
                logger.error("Failed to load data")
                return False

            # Preprocess data
            X_train, X_test, y_train, y_test = self.preprocessor.preprocess_data(df)

            # Store processed data
            self.X_train = X_train
            self.X_test = X_test
            self.y_train = y_train
            self.y_test = y_test
            self.raw_data = df

            self.data_loaded = True
            logger.info(f"Data loaded successfully. Shape: {df.shape}")
            logger.info(f"Class distribution: {df['Label'].value_counts().to_dict()}")

            return True

        except Exception as e:
            logger.error(f"Error loading data: {e}")
            return False

    def train_models(self) -> bool:
        """
        Train anomaly detection models

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.data_loaded:
            logger.error("Data must be loaded before training models")
            return False

        try:
            logger.info("Training models...")

            # Create models
            self.detector.models = self.detector.create_models()

            # Train supervised models
            training_results = {}
            supervised_models = ['random_forest', 'svm']

            for model_name in supervised_models:
                if model_name in self.detector.models:
                    results = self.detector.train_model(
                        model_name, self.X_train, self.y_train
                    )
                    training_results[model_name] = results

                    # Save trained model
                    self.detector.save_model(model_name)

            self.models_trained = True
            self.training_results = training_results

            logger.info("Model training completed successfully")
            self._display_training_results(training_results)

            return True

        except Exception as e:
            logger.error(f"Error training models: {e}")
            return False

    def _display_training_results(self, results: Dict):
        """Display training results in a formatted way"""
        logger.info("\n" + "="*50)
        logger.info("MODEL TRAINING RESULTS")
        logger.info("="*50)

        for model_name, result in results.items():
            logger.info(f"\n{model_name.upper()}:")
            logger.info(f"  Training Accuracy: {result['training_accuracy']:.4f}")
            if result['feature_importance'] is not None:
                logger.info(f"  Feature Importance Shape: {result['feature_importance'].shape}")

        logger.info("="*50)

    def detect_attacks(self, data: pd.DataFrame, model_name: str = 'random_forest') -> Dict:
        """
        Detect DoS attacks in the provided data

        Args:
            data: DataFrame with network traffic features
            model_name: Name of the model to use for detection

        Returns:
            dict: Detection results
        """
        if not self.models_trained:
            logger.error("Models must be trained before detection")
            return {'error': 'Models not trained'}

        try:
            logger.info(f"Detecting attacks using {model_name} model...")

            # Set preprocessor reference in detector
            self.detector.preprocessor = self.preprocessor

            # Preprocess input data using the detector's method
            X = self.detector.preprocess_new_data(data)

            # Make predictions
            predictions, scores = self.detector.predict_anomaly(model_name, X)

            # Detect DoS attacks
            detection_results = self.detector.detect_dos_attack(X, model_name)

            # Classify attack types
            attack_types = []
            for i, pred in enumerate(predictions):
                if pred == 1:  # Attack detected
                    features = X[i]
                    feature_names = data.columns.tolist()
                    attack_type = self.classifier.classify_attack(features, feature_names)
                    attack_types.append(attack_type)
                else:
                    attack_types.append('Normal')

            # Check for alerts
            alert = self.alert_system.check_alert(detection_results)

            results = {
                'predictions': predictions.tolist(),
                'scores': scores.tolist(),
                'attack_types': attack_types,
                'detection_summary': detection_results,
                'alert': alert,
                'model_used': model_name
            }

            logger.info("Attack detection completed")
            logger.info(self.detector.get_attack_summary(detection_results))

            return results

        except Exception as e:
            logger.error(f"Error during attack detection: {e}")
            return {'error': str(e)}

    def start_realtime_monitoring(self):
        """Start real-time monitoring"""
        if not self.models_trained:
            logger.error("Models must be trained before monitoring")
            return False

        try:
            self.monitor.start_monitoring()
            self.monitoring_active = True
            logger.info("Real-time monitoring started")
            return True
        except Exception as e:
            logger.error(f"Error starting monitoring: {e}")
            return False

    def stop_realtime_monitoring(self):
        """Stop real-time monitoring"""
        try:
            self.monitor.stop_monitoring()
            self.monitoring_active = False
            logger.info("Real-time monitoring stopped")
            return True
        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")
            return False

    def get_system_status(self) -> Dict:
        """Get current system status"""
        status = {
            'data_loaded': self.data_loaded,
            'models_trained': self.models_trained,
            'monitoring_active': self.monitoring_active,
            'config': self.config
        }

        if hasattr(self, 'raw_data'):
            status['data_shape'] = self.raw_data.shape
            status['class_distribution'] = self.raw_data['Label'].value_counts().to_dict()

        if self.monitoring_active:
            status['monitoring_stats'] = self.monitor.get_monitoring_stats()

        return status

    def run_demo(self):
        """Run a complete demonstration of the system"""
        logger.info("Starting DoS Detection System Demo")
        logger.info("="*60)

        # Step 1: Load data
        logger.info("Step 1: Loading data...")
        if not self.load_data():
            return False

        # Step 2: Train models
        logger.info("Step 2: Training models...")
        if not self.train_models():
            return False

        # Step 3: Test detection
        logger.info("Step 3: Testing attack detection...")
        sample_data = self.raw_data.drop('Label', axis=1).head(100)  # Test on first 100 samples
        results = self.detect_attacks(sample_data)

        if 'error' not in results:
            logger.info("Demo completed successfully!")
            logger.info(f"Sample predictions: {results['predictions'][:10]}")
            logger.info(f"Detection Summary: {results['detection_summary']}")
        else:
            logger.error(f"Detection failed: {results['error']}")

        return True

def create_argument_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description='DoS Attack Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo                    # Run complete demo
  python main.py --train                  # Load data and train models
  python main.py --detect --input-file data/sample.csv  # Detect attacks in file
  python main.py --dashboard              # Launch web dashboard
  python main.py --status                 # Show system status
        """
    )

    parser.add_argument('--config', default='config/config.yaml',
                       help='Path to configuration file (default: config/config.yaml)')

    parser.add_argument('--demo', action='store_true',
                       help='Run complete system demonstration')

    parser.add_argument('--train', action='store_true',
                       help='Load data and train models')

    parser.add_argument('--detect', action='store_true',
                       help='Detect attacks in input file')

    parser.add_argument('--input-file', type=str,
                       help='Input file for attack detection (CSV format)')

    parser.add_argument('--dashboard', action='store_true',
                       help='Launch web dashboard')

    parser.add_argument('--status', action='store_true',
                       help='Show system status')

    parser.add_argument('--model', default='random_forest',
                       choices=['random_forest', 'svm', 'isolation_forest', 'one_class_svm'],
                       help='Model to use for detection (default: random_forest)')

    return parser

def main():
    """Main function"""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Initialize system
    system = DoSDetectionSystem(args.config)

    if args.demo:
        # Run complete demo
        success = system.run_demo()
        sys.exit(0 if success else 1)

    elif args.train:
        # Load data and train models
        if system.load_data() and system.train_models():
            logger.info("Training completed successfully")
            sys.exit(0)
        else:
            logger.error("Training failed")
            sys.exit(1)

    elif args.detect:
        # Detect attacks
        if not args.input_file:
            logger.error("Input file required for detection (--input-file)")
            sys.exit(1)

        if not system.data_loaded or not system.models_trained:
            logger.info("Loading data and training models first...")
            if not (system.load_data() and system.train_models()):
                logger.error("Failed to initialize system")
                sys.exit(1)

        # Load input data
        try:
            input_data = pd.read_csv(args.input_file)
            results = system.detect_attacks(input_data, args.model)

            if 'error' in results:
                logger.error(f"Detection failed: {results['error']}")
                sys.exit(1)
            else:
                logger.info("Detection Results:")
                logger.info(f"Attack Ratio: {results['detection_summary']['attack_percentage']:.2f}%")
                logger.info(f"Total Samples: {results['detection_summary']['total_samples']}")
                logger.info(f"Attacks Detected: {results['detection_summary']['attack_count']}")

        except Exception as e:
            logger.error(f"Error processing input file: {e}")
            sys.exit(1)

    elif args.dashboard:
        # Launch dashboard
        try:
            import streamlit as st
            from src.dashboard.app import DashboardApp

            logger.info("Launching dashboard...")
            dashboard = DashboardApp()
            dashboard.run()

        except ImportError:
            logger.error("Streamlit not installed. Install with: pip install streamlit")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error launching dashboard: {e}")
            sys.exit(1)

    elif args.status:
        # Show system status
        status = system.get_system_status()
        logger.info("System Status:")
        for key, value in status.items():
            if key != 'config':  # Skip config for brevity
                logger.info(f"  {key}: {value}")

    else:
        # No arguments provided, show help
        parser.print_help()

if __name__ == "__main__":
    main()