import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import time
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# Import our modules
from src.preprocessing.data_preprocessor import DataPreprocessor
from src.detection.anomaly_detector import AnomalyDetector
from src.detection.detection_utils import RealTimeMonitor, AttackClassifier, AlertSystem

# Set page configuration
st.set_page_config(
    page_title="DoS Attack Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 0.25rem solid #1f77b4;
    }
    .alert-card {
        background-color: #ffe6e6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 0.25rem solid #ff4444;
    }
    .normal-card {
        background-color: #e6ffe6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 0.25rem solid #44ff44;
    }
</style>
""", unsafe_allow_html=True)

class DashboardApp:
    def __init__(self):
        self.preprocessor = DataPreprocessor()
        self.detector = AnomalyDetector()
        self.monitor = RealTimeMonitor()
        self.classifier = AttackClassifier()
        self.alert_system = AlertSystem()

        # Initialize session state
        if 'data_loaded' not in st.session_state:
            st.session_state.data_loaded = False
        if 'models_trained' not in st.session_state:
            st.session_state.models_trained = False
        if 'monitoring_active' not in st.session_state:
            st.session_state.monitoring_active = False

    def run(self):
        """Main dashboard application"""
        st.markdown('<h1 class="main-header">🛡️ DoS Attack Detection System</h1>', unsafe_allow_html=True)

        # Sidebar navigation
        self.sidebar_navigation()

        # Main content
        self.main_content()

    def sidebar_navigation(self):
        """Sidebar with navigation and controls"""
        st.sidebar.title("Navigation")

        page = st.sidebar.radio(
            "Select Page",
            ["Dashboard", "Data Management", "Model Training", "Real-time Monitoring", "Reports"]
        )

        st.sidebar.markdown("---")

        # System controls
        st.sidebar.subheader("System Controls")

        if st.sidebar.button("Load Data", type="primary"):
            self.load_data()

        if st.sidebar.button("Train Models", disabled=not st.session_state.data_loaded):
            self.train_models()

        if st.sidebar.button("Start Monitoring", disabled=not st.session_state.models_trained):
            self.start_monitoring()

        if st.sidebar.button("Stop Monitoring", disabled=not st.session_state.monitoring_active):
            self.stop_monitoring()

        # System status
        st.sidebar.markdown("---")
        st.sidebar.subheader("System Status")

        status_data = {
            "Data Loaded": "✅" if st.session_state.data_loaded else "❌",
            "Models Trained": "✅" if st.session_state.models_trained else "❌",
            "Monitoring Active": "✅" if st.session_state.monitoring_active else "❌"
        }

        for status, icon in status_data.items():
            st.sidebar.write(f"{icon} {status}")

    def main_content(self):
        """Main content area"""
        # Overview metrics
        self.display_overview_metrics()

        # Real-time status
        self.display_realtime_status()

        # Recent alerts
        self.display_recent_alerts()

        # Traffic visualization
        self.display_traffic_visualization()

    def load_data(self):
        """Load and preprocess data"""
        with st.spinner("Loading data..."):
            try:
                # Generate simulated data for demonstration
                df = self.preprocessor.generate_simulated_dos_data()

                # Preprocess the data
                X_train, X_test, y_train, y_test = self.preprocessor.preprocess_data(df)

                # Store in session state
                st.session_state.data = df
                st.session_state.X_train = X_train
                st.session_state.X_test = X_test
                st.session_state.y_train = y_train
                st.session_state.y_test = y_test
                st.session_state.data_loaded = True

                st.success(f"Data loaded successfully! Shape: {df.shape}")
                st.info(f"Class distribution: {df['Label'].value_counts().to_dict()}")

            except Exception as e:
                st.error(f"Error loading data: {e}")

    def train_models(self):
        """Train anomaly detection models"""
        with st.spinner("Training models..."):
            try:
                # Create models
                self.detector.models = self.detector.create_models()

                # Train each model
                training_results = {}
                for model_name in self.detector.models.keys():
                    if model_name in ['random_forest', 'svm']:  # Only train supervised models
                        results = self.detector.train_model(
                            model_name,
                            st.session_state.X_train,
                            st.session_state.y_train
                        )
                        training_results[model_name] = results

                st.session_state.models_trained = True
                st.session_state.training_results = training_results

                st.success("Models trained successfully!")

                # Display training results
                for model_name, results in training_results.items():
                    st.write(f"**{model_name.upper()}**: Accuracy = {results['training_accuracy']:.4f}")

            except Exception as e:
                st.error(f"Error training models: {e}")

    def start_monitoring(self):
        """Start real-time monitoring"""
        try:
            self.monitor.start_monitoring()
            st.session_state.monitoring_active = True
            st.success("Real-time monitoring started!")
        except Exception as e:
            st.error(f"Error starting monitoring: {e}")

    def stop_monitoring(self):
        """Stop real-time monitoring"""
        try:
            self.monitor.stop_monitoring()
            st.session_state.monitoring_active = False
            st.success("Real-time monitoring stopped!")
        except Exception as e:
            st.error(f"Error stopping monitoring: {e}")

    def display_overview_metrics(self):
        """Display overview metrics"""
        st.subheader("📊 System Overview")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Total Samples",
                len(st.session_state.get('data', pd.DataFrame())),
                help="Total number of network traffic samples"
            )

        with col2:
            attack_count = 0
            if 'data' in st.session_state:
                attack_count = (st.session_state.data['Label'] == 'DoS').sum()
            st.metric(
                "Attack Samples",
                attack_count,
                help="Number of DoS attack samples"
            )

        with col3:
            normal_count = 0
            if 'data' in st.session_state:
                normal_count = (st.session_state.data['Label'] == 'BENIGN').sum()
            st.metric(
                "Normal Samples",
                normal_count,
                help="Number of normal traffic samples"
            )

        with col4:
            attack_ratio = 0
            if 'data' in st.session_state and len(st.session_state.data) > 0:
                attack_ratio = (attack_count / len(st.session_state.data)) * 100
            st.metric(
                "Attack Ratio",
                f"{attack_ratio:.1f}%",
                help="Percentage of attack traffic"
            )

    def display_realtime_status(self):
        """Display real-time system status"""
        st.subheader("🔴 Real-time Status")

        if st.session_state.monitoring_active:
            # Get monitoring stats
            stats = self.monitor.get_monitoring_stats()

            if stats['total_samples'] > 0:
                col1, col2, col3 = st.columns(3)

                with col1:
                    if stats['attack_ratio'] > 0.5:
                        st.markdown('<div class="alert-card">', unsafe_allow_html=True)
                        st.error("⚠️ ATTACK DETECTED")
                        st.markdown('</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="normal-card">', unsafe_allow_html=True)
                        st.success("✅ NORMAL TRAFFIC")
                        st.markdown('</div>', unsafe_allow_html=True)

                with col2:
                    st.metric(
                        "Attack Ratio",
                        f"{stats['attack_ratio']:.1%}",
                        help="Current attack traffic ratio"
                    )

                with col3:
                    st.metric(
                        "Samples Analyzed",
                        stats['total_samples'],
                        help="Number of samples in current window"
                    )
            else:
                st.info("Waiting for traffic data...")
        else:
            st.info("Real-time monitoring is not active")

    def display_recent_alerts(self):
        """Display recent alerts"""
        st.subheader("🚨 Recent Alerts")

        alerts = self.alert_system.get_active_alerts()

        if alerts:
            for alert in alerts[-5:]:  # Show last 5 alerts
                timestamp = datetime.fromtimestamp(alert['timestamp']).strftime('%H:%M:%S')
                st.warning(f"[{timestamp}] {alert['alert_type']} - {alert['message']}")
        else:
            st.success("No active alerts")

    def display_traffic_visualization(self):
        """Display traffic visualization"""
        st.subheader("📈 Traffic Analysis")

        if 'data' not in st.session_state:
            st.info("Please load data first")
            return

        data = st.session_state.data

        col1, col2 = st.columns(2)

        with col1:
            # Class distribution pie chart
            fig = px.pie(
                data,
                names='Label',
                title='Traffic Class Distribution',
                color_discrete_sequence=['#1f77b4', '#ff7f0e']
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            # Feature correlation heatmap (sample of features)
            numeric_cols = data.select_dtypes(include=[np.number]).columns[:10]
            corr_matrix = data[numeric_cols].corr()

            fig = px.imshow(
                corr_matrix,
                title='Feature Correlation Matrix',
                color_continuous_scale='RdBu_r'
            )
            st.plotly_chart(fig, use_container_width=True)

def main():
    """Main function to run the dashboard"""
    app = DashboardApp()
    app.run()

if __name__ == "__main__":
    main()