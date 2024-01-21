import subprocess
import platform
import requests

def check_network_connection():
    ip_address = "8.8.8.8"
    
    # Determine the command based on the operating system
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip_address]

    try:
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = response.returncode == 0
        return result
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def check_virustotal_connection():
    url = "https://www.virustotal.com"
    try:
        response = requests.get(url)
        result = response.status_code == 200
        return result
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return False