# train_model.py

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from imblearn.over_sampling import SMOTE
from sklearn.metrics import roc_curve

def load_data(data_path):
    """
    Load and preprocess your dataset.

    :param data_path: Path to the dataset CSV file.
    :return: X (features), y (labels)
    """
    # Load your dataset (replace with your data loading logic)
    df = pd.read_csv(data_path)

    # Preprocess your data (replace with your data preprocessing logic)
    X = df.drop(columns=['target'])  # Replace 'target' with your target column name
    y = df['target']  # Replace 'target' with your target column name

    return X, y

def preprocess_data(X):
    """
    Preprocess the data (e.g., handle missing values, encode categorical variables).

    :param X: Features DataFrame.
    :return: Preprocessed X.
    """
    # Add your data preprocessing logic here
    return X

def oversample_data(X, y):
    """
    Apply oversampling to handle class imbalance.

    :param X: Features DataFrame.
    :param y: Labels.
    :return: Oversampled X, y.
    """
    smote = SMOTE(sampling_strategy='auto', random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y)
    return X_resampled, y_resampled

def train_model(X_train, y_train):
    """
    Train a machine learning model.

    :param X_train: Training features.
    :param y_train: Training labels.
    :return: Trained model.
    """
    # Create and train your model (replace with your model training code)
    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)
    return model

def evaluate_model(model, X_test, y_test):
    """
    Evaluate the trained model.

    :param model: Trained model
    :param X_test: Test features
    :param y_test: Test labels
    """
    # Make predictions on the test set
    y_pred = model.predict(X_test)

    # Evaluate the model's performance
    accuracy = accuracy_score(y_test, y_pred)
    classification_rep = classification_report(y_test, y_pred)
    confusion_mat = confusion_matrix(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred)

    print(f"Model Accuracy: {accuracy:.2f}")
    print(f"Classification Report:\n{classification_rep}")
    print(f"Confusion Matrix:\n{confusion_mat}")
    print(f"ROC AUC Score: {roc_auc:.2f}")

    # Additional Visualization
    plot_roc_curve(y_test, y_pred)
    plot_feature_importances(model, X_test.columns, save_path='feature_importances.png')
    plot_confusion_matrix(confusion_mat, classes=['Class 0', 'Class 1'], title='Confusion Matrix')

def plot_roc_curve(y_true, y_pred):
    """
    Plot the ROC curve.

    :param y_true: True labels
    :param y_pred: Predicted probabilities
    """
    fpr, tpr, thresholds = roc_curve(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label='ROC Curve', linewidth=2, color='b')
    plt.plot([0, 1], [0, 1], 'k--', linewidth=2)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc='lower right')
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.show()

def plot_feature_importances(model, feature_names, save_path=None):
    """
    Plot and optionally save feature importances.

    :param model: Trained model with feature_importances_ attribute
    :param feature_names: List of feature names
    :param save_path: Path to save the plot (optional)
    """
    feature_importances = model.feature_importances_
    sorted_indices = np.argsort(feature_importances)[::-1]
    sorted_importances = feature_importances[sorted_indices]
    sorted_features = np.array(feature_names)[sorted_indices]

    plt.figure(figsize=(12, 6))
    sns.barplot(x=sorted_importances, y=sorted_features, palette='viridis')
    plt.title("Feature Importances")
    plt.xlabel("Importance")
    plt.ylabel("Feature")
    plt.xticks(rotation=90)
    plt.grid(axis='x', linestyle='--', alpha=0.6)

    if save_path:
        plt.tight_layout()
        plt.savefig(save_path, bbox_inches='tight', dpi=300)
        print(f"Feature importances plot saved as {save_path}")
    else:
        plt.show()

def plot_confusion_matrix(cm, classes, title='Confusion Matrix'):
    """
    Plot the confusion matrix.

    :param cm: Confusion matrix
    :param classes: Class labels
    :param title: Title for the plot
    """
    plt.figure(figsize=(8, 6))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45)
    plt.yticks(tick_marks, classes)
    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.show()

if __name__ == "__main__":
    # Specify your dataset path
    dataset_path = 'your_dataset.csv'

    # Load and preprocess the dataset
    X, y = load_data(dataset_path)
    X = preprocess_data(X)

    # Apply oversampling to handle class imbalance
    X, y = oversample_data(X, y)

    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Train the model
    trained_model = train_model(X_train, y_train)

    # Evaluate the model
    evaluate_model(trained_model, X_test, y_test)

    # Save the model
    joblib.dump(trained_model, 'trained_model.pkl')
