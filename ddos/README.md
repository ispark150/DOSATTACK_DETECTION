# 🛡️ DoS Attack Detection System

A comprehensive Denial-of-Service (DoS) attack detection system built with Python and scikit-learn, featuring real-time monitoring, multiple detection algorithms, and an interactive web dashboard.

## 🚀 Features

- **Multiple Detection Algorithms**: Random Forest, SVM, Isolation Forest, and One-Class SVM
- **Real-time Monitoring**: Continuous traffic analysis with attack pattern detection
- **Interactive Dashboard**: Web-based interface for visualization and monitoring
- **CICIDS2017 Support**: Compatible with the popular CICIDS2017 dataset
- **Simulated Data Generation**: Built-in synthetic data generator for testing
- **Alert System**: Automated alerting for detected attacks
- **Attack Classification**: Identifies specific types of DoS attacks
- **Model Persistence**: Save and load trained models

## 📋 Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`

## 🛠️ Installation

1. Clone or download the project files
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Quick Start

### Run Complete Demo
```bash
python main.py --demo
```

### Train Models
```bash
python main.py --train
```

### Launch Dashboard
```bash
python main.py --dashboard
```

### Detect Attacks in Custom Data
```bash
python main.py --detect --input-file your_data.csv --model random_forest
```

## 📖 Usage

### Command Line Interface

```bash
# Show help
python main.py --help

# Run demonstration
python main.py --demo

# Load data and train models
python main.py --train

# Launch web dashboard
python main.py --dashboard

# Show system status
python main.py --status

# Detect attacks in CSV file
python main.py --detect --input-file data/traffic.csv --model svm
```

### Python API

```python
from main import DoSDetectionSystem

# Initialize system
system = DoSDetectionSystem()

# Load data (uses simulated data if no path provided)
system.load_data()

# Train models
system.train_models()

# Detect attacks
results = system.detect_attacks(your_dataframe)
print(results['detection_summary'])
```

## 🏗️ System Architecture

```
├── config/
│   └── config.yaml          # System configuration
├── src/
│   ├── preprocessing/
│   │   ├── data_preprocessor.py    # Data loading and preprocessing
│   │   └── __init__.py
│   ├── detection/
│   │   ├── anomaly_detector.py     # ML models and detection
│   │   ├── detection_utils.py      # Monitoring and classification
│   │   └── __init__.py
│   └── dashboard/
│       ├── app.py                  # Streamlit dashboard
│       └── __init__.py
├── models/                  # Trained model storage
├── data/                    # Dataset storage
├── main.py                  # Main application entry point
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔧 Configuration

The system uses a YAML configuration file (`config/config.yaml`) for settings:

```yaml
data:
  use_simulated: true          # Use simulated data for testing
  simulated_samples: 10000     # Number of simulated samples
  test_size: 0.2              # Train/test split ratio

models:
  random_forest:
    n_estimators: 100
    max_depth: 10
  svm:
    kernel: 'rbf'
    C: 1.0

detection:
  dos_threshold: 0.7          # Attack detection threshold
```

## 📊 Detection Models

### Supervised Models
- **Random Forest**: Ensemble method, good for feature importance
- **Support Vector Machine**: Effective for high-dimensional data

### Unsupervised Models
- **Isolation Forest**: Good for anomaly detection
- **One-Class SVM**: Novelty detection

## 🎯 Attack Types Detected

- SYN Flood
- UDP Flood
- HTTP Flood
- ICMP Flood
- Generic DoS attacks

## 📈 Dashboard Features

- Real-time traffic monitoring
- Attack detection visualization
- Model performance metrics
- Alert management
- Traffic pattern analysis
- System status monitoring

## 🔍 Data Format

The system expects network traffic data with features such as:

- Source/Destination Ports
- Protocol
- Packet lengths and counts
- Flow duration and rates
- TCP flags and states
- Label (BENIGN or attack type)

### CICIDS2017 Dataset

To use the real CICIDS2017 dataset:
1. Download from the official source
2. Place CSV files in the `data/` directory
3. Update `config.yaml` to point to your data files
4. Set `use_simulated: false`

## 📝 Logging

The system logs all activities to `dos_detection.log` and console output. Log levels can be configured in the configuration file.

## 🚨 Alerts

The system generates alerts when:
- Attack traffic exceeds threshold
- Sudden traffic spikes detected
- Abnormal patterns identified

## 🔧 Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed
   ```bash
   pip install -r requirements.txt
   ```

2. **Memory Issues**: Reduce simulated data size in config
   ```yaml
   data:
     simulated_samples: 5000
   ```

3. **Model Training Fails**: Check data format and preprocessing

### Performance Tips

- Use smaller datasets for faster training
- Random Forest is faster than SVM for large datasets
- Enable SMOTE for better class balancing

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is provided as-is for educational and research purposes.

## 📚 References

- CICIDS2017 Dataset: https://www.unb.ca/cic/datasets/ids-2017.html
- Scikit-learn Documentation: https://scikit-learn.org/
- Streamlit Documentation: https://docs.streamlit.io/

## 🆘 Support

For issues and questions:
1. Check the logs in `dos_detection.log`
2. Verify configuration settings
3. Test with simulated data first
4. Review the troubleshooting section

---

**Note**: This system is designed for research and educational purposes. For production use, additional security measures and validation would be required.