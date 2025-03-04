import requests
import socket
import subprocess
import platform
import json
import os
from datetime import datetime

from db_operations import db_vt_api_keys

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

def check_network_access():
    # Checks basic network connectivity to VirusTotal.
    # Ensures that the host is reachable via HTTPS (port 443).
    print("\n[INFO] Checking network connectivity to VirusTotal...")
    try:
        socket.create_connection(("www.virustotal.com", 443), timeout=3)
        print("[SUCCESS] Network connection to VirusTotal is available.")
        return True
    except OSError:
        print("[ERROR] Unable to establish a network connection to VirusTotal. Check your internet or firewall settings.")
        return False

def check_virustotal_website():
    # Checks if the VirusTotal website is accessible via HTTP request.
    vt_url = 'https://www.virustotal.com'
    print("[INFO] Checking HTTP access to VirusTotal...")
    try:
        response = requests.get(vt_url, timeout=5)
        if response.status_code == 200:
            print("[SUCCESS] VirusTotal website is accessible.")
            return True
        else:
            print(f"[WARNING] VirusTotal is reachable, but returned status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"[ERROR] Unable to access VirusTotal's website: {e}")
        return False

def check_virustotal_api():
    """
    Checks access to the VirusTotal API by cycling through all available API keys.
    Ensures that at least one key is valid before failing.
    """
    api_url = 'https://www.virustotal.com/api/v3/users/me'
    timestamp = datetime.now().strftime("%B %d %Y %I:%M %p")

    print(f"\nTime: {timestamp}")
    print("=" * 90)
    print(f"{'API Key'.ljust(64)} | {'Status'}")
    print("=" * 90)

    # Fetch all available API keys from the database
    api_keys = db_vt_api_keys.get_virustotal_api_keys()
    
    if not api_keys:
        print("[ERROR] No available API keys found. Cannot check VirusTotal API.")
        return False

    success_keys = []  # Stores working API keys
    failed_keys = []  # Stores invalid API keys

    for key_data in api_keys:
        key = key_data[1]
        key_id = key_data[0]
        headers = {"x-apikey": key}

        print(f"{key.ljust(64)} | Checking...", end="")

        try:
            api_response = requests.get(api_url, headers=headers, timeout=5)
            status_code = api_response.status_code

            if status_code == 200:
                print("[SUCCESS] API Key Valid")
                success_keys.append(key)
                
            elif status_code == 401:
                print("[WARNING] Invalid API Key")
                failed_keys.append(key)

            else:
                print(f"[ERROR] Unexpected Status: {status_code}")
                failed_keys.append(key)

        except requests.RequestException as e:
            print(f"[ERROR] Request Failed: {e}")
            failed_keys.append(key)

    print("=" * 90)
    
    if success_keys:
        print(f"\n[INFO] {len(success_keys)} API key(s) are working:")
        for key in success_keys:
            print(f"   - {key}")

    if failed_keys:
        print(f"\n[WARNING] {len(failed_keys)} API key(s) are invalid:")
        for key in failed_keys:
            print(f"   - {key}")

def check_virustotal_access():
    # Runs all checks: network access, website access, and API access.
    if not check_network_access():
        return False
    if not check_virustotal_website():
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
