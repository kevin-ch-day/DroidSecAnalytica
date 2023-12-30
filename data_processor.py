import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from imblearn.over_sampling import SMOTE
from joblib import Parallel, delayed

def preprocess_permissions(permissions_df):
    """
    Preprocess the permissions dataset for advanced analysis.

    Args:
        permissions_df (pd.DataFrame): DataFrame containing permissions data.

    Returns:
        dict: Processed data, including X_train, X_test, y_train, and y_test.
    """
    # Encode labels (e.g., 'malware' and 'benign') into numerical values
    label_encoder = LabelEncoder()
    permissions_df['label'] = label_encoder.fit_transform(permissions_df['label'])

    # Split the dataset into features (X) and labels (y)
    X = permissions_df.drop('label', axis=1)
    y = permissions_df['label']

    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Use TF-IDF vectorization to convert permissions into numerical features
    tfidf_vectorizer = TfidfVectorizer()

    # Parallelize TF-IDF vectorization for improved performance
    X_train_tfidf, X_test_tfidf = parallelize_tfidf_vectorization(X_train['permissions'], X_test['permissions'], tfidf_vectorizer)

    # Standardize numerical features (if any)
    scaler = StandardScaler()

    # Parallelize standardization for improved performance
    X_train_scaled, X_test_scaled = parallelize_standardization(X_train[['numerical_feature_1', 'numerical_feature_2']],
                                                               X_test[['numerical_feature_1', 'numerical_feature_2']],
                                                               scaler)

    # Combine TF-IDF and standardized features
    X_train_final = pd.concat([pd.DataFrame(X_train_tfidf.toarray()), pd.DataFrame(X_train_scaled)], axis=1)
    X_test_final = pd.concat([pd.DataFrame(X_test_tfidf.toarray()), pd.DataFrame(X_test_scaled)], axis=1)

    # Apply Synthetic Minority Over-sampling Technique (SMOTE) for class imbalance
    smote = SMOTE(random_state=42)

    # Parallelize SMOTE resampling for improved performance
    X_train_final_resampled, y_train_resampled = parallelize_smote_resampling(X_train_final, y_train, smote)

    # Return processed data as a dictionary
    processed_data = {
        'X_train': X_train_final_resampled,
        'X_test': X_test_final,
        'y_train': y_train_resampled,
        'y_test': y_test
    }

    return processed_data

def parallelize_tfidf_vectorization(train_data, test_data, vectorizer):
    """
    Parallelize TF-IDF vectorization.

    Args:
        train_data (pd.Series): Training data for vectorization.
        test_data (pd.Series): Testing data for vectorization.
        vectorizer: TF-IDF vectorizer.

    Returns:
        tuple: Tuple containing TF-IDF transformed training and testing data.
    """
    def tfidf_vectorization(data):
        return vectorizer.transform(data)

    # Use joblib to parallelize vectorization
    X_train_tfidf = Parallel(n_jobs=-1)(delayed(tfidf_vectorization)(train_data) for train_data in [train_data])
    X_test_tfidf = Parallel(n_jobs=-1)(delayed(tfidf_vectorization)(test_data) for test_data in [test_data])

    return X_train_tfidf[0], X_test_tfidf[0]

def parallelize_standardization(train_data, test_data, scaler):
    """
    Parallelize standardization.

    Args:
        train_data (pd.DataFrame): Training data for standardization.
        test_data (pd.DataFrame): Testing data for standardization.
        scaler: StandardScaler.

    Returns:
        tuple: Tuple containing standardized training and testing data.
    """
    def standardization(data):
        return scaler.transform(data)

    # Use joblib to parallelize standardization
    X_train_scaled = Parallel(n_jobs=-1)(delayed(standardization)(train_data) for train_data in [train_data])
    X_test_scaled = Parallel(n_jobs=-1)(delayed(standardization)(test_data) for test_data in [test_data])

    return X_train_scaled[0], X_test_scaled[0]

def parallelize_smote_resampling(X, y, smote):
    """
    Parallelize SMOTE resampling.

    Args:
        X (pd.DataFrame): Data for resampling.
        y (pd.Series): Labels for resampling.
        smote: SMOTE object.

    Returns:
        tuple: Tuple containing resampled data and labels.
    """
    def smote_resampling(data):
        X_resampled, y_resampled = smote.fit_resample(X, y)
        return X_resampled, y_resampled

    # Use joblib to parallelize SMOTE resampling
    X_resampled, y_resampled = Parallel(n_jobs=-1)(delayed(smote_resampling)(X) for X in [X])

    return X_resampled[0], y_resampled[0]
