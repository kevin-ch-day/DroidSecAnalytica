import requests
import socket
import subprocess
import platform
import json
import os
from datetime import datetime

def check_ping():
    ip = "8.8.8.8"
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ["ping", param, "1", ip]

    try:
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if response.returncode == 0:
            print(f"Successfully pinged {ip}.")
            return True
        else:
            print(f"Failed to ping {ip}. Response: {response.stderr}")
            return False
    except Exception as e:
        print(f"An error occurred while trying to ping: {e}")
        return False

def check_virustotal_access():
    url = 'https://www.virustotal.com'
    try:
        host = socket.gethostbyname('www.virustotal.com')
        print("DNS resolution successful.")
    except socket.gaierror:
        print("Failed to resolve VirusTotal's domain. Check your DNS settings.")
        return False

    try:
        socket.create_connection((host, 80), 2)
        print("Network connection to VirusTotal established.")
    except OSError:
        print("Network connection to VirusTotal failed. Check your network.")
        return False

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print("Successfully connected to VirusTotal.")
            return True
        else:
            print(f"Connected to VirusTotal, but received a non-success status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"HTTP request to VirusTotal failed: {e}")
        return False

def set_data_if_key_exists(key, setter_function, data):
    if key in data:
        setter_function(data[key])

def add_items_to_list_if_key_exists(key, add_function, data):
    if key in data:
        for item in data[key]:
            add_function(item)

def save_json_response(response, filename, overwrite=True):
    print(filename)
    if not isinstance(response, dict):
        print("Error: Response must be a dictionary.")
        return

    try:
        if os.path.exists(filename) and not overwrite:
            print(f"File '{filename}' already exists. Use 'overwrite=True' to overwrite.")
            return

        with open(filename, 'w') as file:
            json.dump(response, file, indent=4)
        print(f"Response saved to '{filename}'")
    except Exception as e:
        print(f"Error saving response to file: {e}")

def format_timestamp(timestamp):
    try:
        # Check if the timestamp is in milliseconds and convert to seconds if necessary
        if isinstance(timestamp, (int, float)) and timestamp > 1e10:
            timestamp /= 1000

        return datetime.fromtimestamp(timestamp).strftime('%I:%M:%S %p %m-%d-%Y') if timestamp else 'N/A'
    except (TypeError, ValueError, OverflowError):
        return 'Invalid Timestamp'

def format_file_size(size):
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"
