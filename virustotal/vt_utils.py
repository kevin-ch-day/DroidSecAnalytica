import requests
import socket
import subprocess
import platform

from utils import logging_utils

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
    
def handle_api_integration():
    try:
        #virustotal_checker = VirustotalChecker()
        virustotal_checker = None
        api_key_valid = virustotal_checker.check_api_key()

        if api_key_valid:
            logging_utils.log_info("Virustotal API Key is valid.")
            print("Virustotal API Key is valid.")
        else:
            logging_utils.log_error("Virustotal API Key is invalid or exceeded the rate limit.")
            print("Virustotal API Key is invalid or exceeded the rate limit.")
    
    except Exception as e:
        logging_utils.log_error(f"An error occurred during Virustotal API Key check: {e}", exc_info=True)
        print("An error occurred during Virustotal API Key check. Please check the logs for more details.")

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
