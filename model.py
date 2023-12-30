# model.py

import logging
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import utils

class APKPermissionModel:
    def __init__(self):
        self.classifier = RandomForestClassifier()
        self.logger = utils.setup_logger("APKPermissionModel")

    def extend_features(self, X_static, X_dynamic):
        """
        Combine static and dynamic features into a single DataFrame.

        :param X_static: DataFrame containing static features from APK analysis.
        :param X_dynamic: DataFrame containing dynamic features from APK analysis.
        :return: Combined DataFrame with all features.
        """
        self.logger.info("Combining static and dynamic features...")
        return pd.concat([X_static, X_dynamic], axis=1)

    def train(self, X, y):
        """
        Train the classifier.

        :param X: DataFrame containing the training features.
        :param y: Series or array containing the labels.
        """
        self.logger.info("Starting model training...")
        self.classifier.fit(X, y)
        self.logger.info("Training completed.")

    def predict(self, X):
        """
        Make predictions using the trained model.

        :param X: DataFrame containing the features for prediction.
        :return: Predicted labels.
        """
        self.logger.info("Making predictions...")
        return self.classifier.predict(X)

    def save_model(self, file_path):
        """
        Save the trained model to a file.

        :param file_path: Path where the model will be saved.
        """
        joblib.dump(self.classifier, file_path)
        self.logger.info(f"Model saved to {file_path}")

    def load_model(self, file_path):
        """
        Load a trained model from a file.

        :param file_path: Path to the model file.
        """
        self.classifier = joblib.load(file_path)
        self.logger.info(f"Model loaded from {file_path}")

# Define the load_model function
def load_model(file_path):
    """
    Load a trained model from a file.

    :param file_path: Path to the model file.
    """
    model = APKPermissionModel()
    model.load_model(file_path)
    return model

if __name__ == "__main__":
    model = APKPermissionModel()
    # Load the data and preprocess it if needed
    X_static = pd.read_csv('static_features.csv')  # Replace with your data file
    X_dynamic = pd.read_csv('dynamic_features.csv')  # Replace with your data file
    y = pd.read_csv('labels.csv')['label']  # Replace with your data file

    # Combining features
    X_combined = model.extend_features(X_static, X_dynamic)

    # Training the model
    model.train(X_combined, y)

    # Saving the model
    model.save_model('apk_permission_model.pkl')
