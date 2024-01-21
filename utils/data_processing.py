# data_processing.py

import datetime
import hashlib
import json
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

def format_timestamp(timestamp, format='%Y-%m-%d %H:%M:%S'):
    # Formats a Unix timestamp into a readable date string
    try:
        return datetime.datetime.fromtimestamp(int(timestamp)).strftime(format)
    except ValueError:
        return 'Invalid Timestamp format.'

def extract_metadata(file_data):
    # Extracts file metadata, handling missing values
    metadata = {
        'File Type': file_data.get('type', 'Unknown'),
        'Upload Date': file_data.get('upload_date', 'Unknown'),
        # Additional metadata fields
    }
    return metadata

def structured_output(data):
    # Formats data into a structured JSON string for output
    try:
        return json.dumps(data, indent=4)
    except TypeError:
        return 'Error in data formatting.'

# Function to format a timestamp as a date string
def format_timestamp(timestamp, format='%Y-%m-%d %H:%M:%S'):
    try:
        formatted_date = datetime.datetime.fromtimestamp(int(timestamp)).strftime(format)
        print(f"Formatted Timestamp: {formatted_date}")
        return formatted_date
    except ValueError:
        print("Invalid Timestamp")
        return 'Invalid Date'

def calculate_hashes(apk_file_path):
    # Check if the file is an APK file
    if not apk_file_path.lower().endswith('.apk'):
        print("The provided file is not an APK file.")
        return False

    hashes = {"MD5": None, "SHA1": None, "SHA256": None}
    try:
        with open(apk_file_path, 'rb') as file:
            file_data = file.read()

        # Calculate and store hashes
        hashes["MD5"] = hashlib.md5(file_data).hexdigest()
        hashes["SHA1"] = hashlib.sha1(file_data).hexdigest()
        hashes["SHA256"] = hashlib.sha256(file_data).hexdigest()

        # Display the hashes
        print("\nAPK Calculated Hashes")
        print("-" * 60)
        print(f"File  : {os.path.basename(apk_file_path)}")
        for hash_type, hash_value in hashes.items():
            print(f"{hash_type:6}: {hash_value}")
        print("-" * 60)

    except FileNotFoundError:
        print(f"Error: The file '{apk_file_path}' does not exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return hashes

# Function to write JSON data to a file
def write_json_to_file(filename, data):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)
    print(f"Data written to file: {filename}")

# Function to extract MD5, SHA1, and SHA256 hashes from a response
def extract_hashes(response_data):
    attributes = response_data.get("data", {}).get("attributes", {})
    md5 = attributes.get("md5", "N/A")
    sha1 = attributes.get("sha1", "N/A")
    sha256 = attributes.get("sha256", "N/A")
    print(f"Extracted Hashes - MD5: {md5}, SHA1: {sha1}, SHA256: {sha256}")
    return {
        "MD5": md5,
        "SHA1": sha1,
        "SHA256": sha256
    }

# Function to calculate vote statistics
def calculate_vote_statistics(last_analysis_stats):
    statistics = {
        "Malicious Votes": last_analysis_stats.get("malicious", 0),
        "Harmless Votes": last_analysis_stats.get("harmless", 0),
        "Suspicious Votes": last_analysis_stats.get("suspicious", 0),
        "Undetected Votes": last_analysis_stats.get("undetected", 0)
    }
    statistics["Total Votes"] = sum(last_analysis_stats.values())
    if statistics["Total Votes"] > 0:
        statistics["Malicious Percentage"] = "{:.2f}%".format(
            (statistics["Malicious Votes"] / statistics["Total Votes"]) * 100
        )
    else:
        statistics["Malicious Percentage"] = "N/A"
    print(f"Vote Statistics: {statistics}")
    return statistics

# Function to extract file metadata
def extract_file_metadata(response_data):
    attributes = response_data.get("data", {}).get("attributes", {})
    first_submission_timestamp = attributes.get("first_submission_date")
    upload_date = format_timestamp(first_submission_timestamp) if first_submission_timestamp else "Unknown"
    last_analysis_timestamp = attributes.get("last_analysis_date")
    latest_report_date = format_timestamp(last_analysis_timestamp) if last_analysis_timestamp else "Unknown"
    reputation = attributes.get("reputation", "N/A")
    file_type = attributes.get("type_description", "Unknown")
    metadata = {
        "File Type": file_type,
        "Upload Date": upload_date,
        "Latest Report": latest_report_date,
        "Community Reputation": reputation
    }
    print(f"Extracted File Metadata: {metadata}")
    return metadata

# Function to classify the threat based on vote statistics
def classify_threat(vote_stats):
    if vote_stats["Malicious Votes"] > vote_stats["Harmless Votes"]:
        classification = "Potentially Malicious"
    elif vote_stats["Suspicious Votes"] > vote_stats["Harmless Votes"]:
        classification = "Suspicious"
    else:
        classification = "Likely Safe"
    print(f"Threat Classification: {classification}")
    return classification

# Function to extract detailed scan results
def extract_detailed_scan_results(last_analysis_results):
    detailed_results = []
    for engine, result in last_analysis_results.items():
        detailed_results.append(f"- {engine}: {result.get('result', 'N/A')}")
    print(f"Detailed Scan Results: {detailed_results}")
    return {"Detailed Scan Results": detailed_results}

# Function to extract and analyze data
def extract_and_analyze_data(response):
    # Extract relevant data from the response
    file_data = response.get("data", {}).get("attributes", {})
    last_analysis_stats = file_data.get("last_analysis_stats", {})
    last_analysis_results = file_data.get("last_analysis_results", {})

    # Initialize an empty analysis dictionary
    analysis = {}

    # Extract and update hash information
    analysis.update(extract_hashes(response))

    # Extract and update file metadata
    analysis.update(extract_file_metadata(file_data))

    # Calculate and update vote statistics
    analysis.update(calculate_vote_statistics(last_analysis_stats))

    # Classify the threat based on vote statistics
    analysis["Classification"] = classify_threat(analysis)

    # Extract and update detailed scan results
    analysis.update(extract_detailed_scan_results(last_analysis_results))

    return analysis

def analyze_data(data):
    total_scans = len(data['data']['attributes']['last_analysis_results'])
    malicious_count = sum(1 for result in data['data']['attributes']['last_analysis_results'].values() if result['category'] == 'malicious')
    benign_count = total_scans - malicious_count
    detection_ratio = malicious_count / total_scans if total_scans > 0 else 0.0

    analysis_results = {
        'Total Scans': total_scans,
        'Malicious Count': malicious_count,
        'Benign Count': benign_count,
        'Detection Ratio': detection_ratio,
    }
    print(f"Analysis Results: {analysis_results}")
    return analysis_results

# Function for advanced data analysis and reporting
def advanced_data_analysis_and_reporting(analysis_df):
    # Save the analyzed data to a CSV file
    analysis_df.to_csv('analysis_results.csv', index=False)
    print("Analysis results saved to 'analysis_results.csv'")

    # Implement machine learning models for predictive analysis
    X = analysis_df[['Malicious Votes', 'Harmless Votes', 'Suspicious Votes', 'Undetected Votes']]
    y = analysis_df['Classification']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    accuracy = model.score(X_test, y_test)
    print(f'Model Accuracy: {accuracy}')