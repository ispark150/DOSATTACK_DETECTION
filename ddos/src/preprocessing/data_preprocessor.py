import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
import logging
import os
import ipaddress
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DataPreprocessor:
    """
    Data preprocessing class for CICIDS2017 dataset and DoS attack detection
    """

    def __init__(self, data_path=None):
        self.data_path = data_path
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.feature_columns = None
        self.target_column = 'Label'
        self.ip_encoders = {}  # Store IP address encoders
        self.categorical_encoders = {}  # Store categorical feature encoders

    def _is_ip_address(self, value):
        """Check if a value is an IP address"""
        try:
            ipaddress.ip_address(str(value))
            return True
        except ValueError:
            return False

    def _ip_to_int(self, ip_str):
        """Convert IP address to integer"""
        try:
            return int(ipaddress.ip_address(str(ip_str)))
        except ValueError:
            return 0

    def _is_hex_value(self, value):
        """Check if a value is hexadecimal"""
        try:
            int(str(value), 16)
            return True
        except (ValueError, TypeError):
            return False

    def _hex_to_int(self, hex_str):
        """Convert hex string to integer"""
        try:
            return int(str(hex_str), 16)
        except (ValueError, TypeError):
            return 0

    def _detect_column_types(self, df):
        """Detect and categorize column types"""
        column_types = {}

        for col in df.columns:
            if col == self.target_column:
                continue

            # Sample values to determine type
            sample_values = df[col].dropna().head(100).values

            # Check if column contains IP addresses
            if any(self._is_ip_address(val) for val in sample_values):
                column_types[col] = 'ip_address'
            # Check if column contains hex values
            elif any(self._is_hex_value(val) for val in sample_values if str(val) != 'nan'):
                column_types[col] = 'hex_value'
            # Check data type
            elif df[col].dtype in ['int64', 'float64']:
                column_types[col] = 'numeric'
            elif df[col].dtype == 'object':
                # Check if it's actually numeric but stored as string
                try:
                    pd.to_numeric(df[col], errors='coerce')
                    column_types[col] = 'numeric_string'
                except:
                    # Check unique values ratio for categorical
                    unique_ratio = df[col].nunique() / len(df[col])
                    if unique_ratio < 0.1:  # Less than 10% unique values
                        column_types[col] = 'categorical'
                    else:
                        column_types[col] = 'text'
            else:
                column_types[col] = 'other'

        return column_types

    def _preprocess_column(self, series, col_type):
        """Preprocess a single column based on its type"""
        if col_type == 'ip_address':
            return series.apply(self._ip_to_int)
        elif col_type == 'hex_value':
            return series.apply(self._hex_to_int)
        elif col_type == 'numeric_string':
            return pd.to_numeric(series, errors='coerce').fillna(0)
        elif col_type == 'categorical':
            if series.name not in self.categorical_encoders:
                self.categorical_encoders[series.name] = LabelEncoder()
                self.categorical_encoders[series.name].fit(series.astype(str))
            return self.categorical_encoders[series.name].transform(series.astype(str))
        elif col_type == 'text':
            # For text features, create simple numeric representation
            if series.name not in self.categorical_encoders:
                self.categorical_encoders[series.name] = LabelEncoder()
                self.categorical_encoders[series.name].fit(series.astype(str))
            return self.categorical_encoders[series.name].transform(series.astype(str))
        else:
            return series

    def load_cicids_data(self, file_path):
        """
        Load CICIDS2017 dataset from CSV file
        """
        try:
            logger.info(f"Loading data from {file_path}")
            df = pd.read_csv(file_path)

            # Basic data info
            logger.info(f"Dataset shape: {df.shape}")
            logger.info(f"Columns: {list(df.columns)}")

            return df
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            return None

    def generate_simulated_dos_data(self, n_samples=10000, n_features=20):
        """
        Generate simulated network traffic data for DoS attack detection
        """
        logger.info(f"Generating simulated dataset with {n_samples} samples")

        # Normal traffic features (lower values, more consistent)
        normal_samples = int(n_samples * 0.7)
        attack_samples = n_samples - normal_samples

        # Feature names similar to CICIDS2017
        feature_names = [
            'Source_IP', 'Destination_IP', 'Source_Port', 'Destination_Port', 'Protocol',
            'Flow_Duration', 'Total_Fwd_Packets', 'Total_Backward_Packets',
            'Total_Length_of_Fwd_Packets', 'Total_Length_of_Bwd_Packets',
            'Fwd_Packet_Length_Max', 'Fwd_Packet_Length_Min', 'Bwd_Packet_Length_Max',
            'Bwd_Packet_Length_Min', 'Flow_Bytes_s', 'Flow_Packets_s', 'Flow_IAT_Mean',
            'Flow_IAT_Std', 'Fwd_IAT_Mean', 'Bwd_IAT_Mean', 'Active_Mean', 'Idle_Mean'
        ]

        # Generate normal traffic
        normal_data = {}
        for feature in feature_names:
            if feature == 'Source_IP':
                # Generate normal source IPs
                normal_data[feature] = [f"192.168.1.{i%254+1}" for i in range(normal_samples)]
            elif feature == 'Destination_IP':
                # Generate normal destination IPs
                normal_data[feature] = [f"10.0.0.{i%254+1}" for i in range(normal_samples)]
            elif 'Port' in feature:
                normal_data[feature] = np.random.randint(1024, 65535, normal_samples)
            elif 'Protocol' in feature:
                normal_data[feature] = np.random.choice([6, 17], normal_samples)  # TCP/UDP
            elif 'Length' in feature or 'Bytes' in feature:
                normal_data[feature] = np.random.exponential(500, normal_samples)
            elif 'Packets' in feature:
                normal_data[feature] = np.random.exponential(10, normal_samples)
            elif 'Duration' in feature or 'IAT' in feature or 'Active' in feature or 'Idle' in feature:
                normal_data[feature] = np.random.exponential(1000, normal_samples)
            else:
                normal_data[feature] = np.random.normal(100, 20, normal_samples)

        # Generate attack traffic (DoS characteristics: high packet rates, short durations)
        attack_data = {}
        for feature in feature_names:
            if feature == 'Source_IP':
                # Generate attack source IPs (more diverse, simulating botnet)
                attack_data[feature] = [f"172.16.{i%255}.{j%255}" for i, j in
                                      zip(range(attack_samples), range(100, 100+attack_samples))]
            elif feature == 'Destination_IP':
                # Attack target (same target for DoS)
                attack_data[feature] = [f"10.0.0.1"] * attack_samples
            elif 'Port' in feature:
                attack_data[feature] = np.random.randint(1024, 65535, attack_samples)
            elif 'Protocol' in feature:
                attack_data[feature] = np.random.choice([6, 17], attack_samples)
            elif 'Length' in feature or 'Bytes' in feature:
                attack_data[feature] = np.random.exponential(1000, attack_samples)  # Higher
            elif 'Packets' in feature:
                attack_data[feature] = np.random.exponential(50, attack_samples)  # Much higher
            elif 'Duration' in feature or 'IAT' in feature:
                attack_data[feature] = np.random.exponential(100, attack_samples)  # Shorter
            elif 'Active' in feature or 'Idle' in feature:
                attack_data[feature] = np.random.exponential(50, attack_samples)  # Shorter
            else:
                attack_data[feature] = np.random.normal(200, 50, attack_samples)  # Higher values

        # Combine data
        normal_df = pd.DataFrame(normal_data)
        normal_df[self.target_column] = 'BENIGN'

        attack_df = pd.DataFrame(attack_data)
        attack_df[self.target_column] = 'DoS'

        # Combine and shuffle
        combined_df = pd.concat([normal_df, attack_df], ignore_index=True)
        combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)

        logger.info(f"Generated dataset shape: {combined_df.shape}")
        logger.info(f"Class distribution: {combined_df[self.target_column].value_counts()}")

        return combined_df

    def preprocess_data(self, df, test_size=0.2, random_state=42, use_smote=True):
        """
        Preprocess the dataset for machine learning
        """
        logger.info("Starting data preprocessing")

        # Handle missing values
        df = df.dropna()
        logger.info(f"After dropping NaN: {df.shape}")

        # Separate features and target
        if self.target_column not in df.columns:
            raise ValueError(f"Target column '{self.target_column}' not found in dataset")

        X = df.drop(self.target_column, axis=1)
        y = df[self.target_column]

        # Store feature columns
        self.feature_columns = X.columns.tolist()

        # Encode target labels
        y_encoded = self.label_encoder.fit_transform(y)
        logger.info(f"Classes: {self.label_encoder.classes_}")

        # Detect column types
        column_types = self._detect_column_types(X)
        logger.info(f"Detected column types: {column_types}")

        # Preprocess each column based on its type
        X_processed = X.copy()
        for col in X.columns:
            if col in column_types:
                col_type = column_types[col]
                logger.info(f"Preprocessing column '{col}' as {col_type}")
                try:
                    X_processed[col] = self._preprocess_column(X[col], col_type)
                except Exception as e:
                    logger.warning(f"Error preprocessing column '{col}': {e}. Using numeric conversion as fallback.")
                    X_processed[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

        # Convert to numeric and handle any remaining issues
        X_processed = X_processed.apply(pd.to_numeric, errors='coerce').fillna(0)

        # Scale all features
        X_processed = self.scaler.fit_transform(X_processed)
        X_processed = pd.DataFrame(X_processed, columns=self.feature_columns, index=X.index)

        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X_processed, y_encoded, test_size=test_size,
            random_state=random_state, stratify=y_encoded
        )

        # Apply SMOTE for class imbalance (optional)
        if use_smote:
            logger.info("Applying SMOTE for class balancing")
            smote = SMOTE(random_state=random_state)
            X_train, y_train = smote.fit_resample(X_train, y_train)
            logger.info(f"After SMOTE - Train shape: {X_train.shape}, Class distribution: {np.bincount(y_train)}")

        logger.info(f"Final shapes - Train: {X_train.shape}, Test: {X_test.shape}")

        return X_train, X_test, y_train, y_test

    def get_feature_names(self):
        """Get the list of feature names"""
        return self.feature_columns

    def get_class_names(self):
        """Get the list of class names"""
        return self.label_encoder.classes_

    def inverse_transform_labels(self, y_encoded):
        """Convert encoded labels back to original labels"""
        return self.label_encoder.inverse_transform(y_encoded)