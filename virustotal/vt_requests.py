# vt_requests.py

import requests

API_KEY = '848c2f7d2499138423f7416f61b8a3e42d8dd9a429ca9bc6f4f478c590c8eec7'

def set_headers():
    return {"x-apikey": API_KEY}

def handle_api_error(e):
    print(f"HTTP Error: {e.response.status_code} - {e.response.reason}")
    if e.response.content:
        print("Error details:", e.response.content.decode())

def query_hash(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = set_headers()
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    
    except requests.HTTPError as e:
        handle_api_error(e)
    
    except requests.ConnectionError:
        print("Connection Error. Please check your network connection.")
    
    except requests.Timeout:
        print("Request Timed Out.")
    
    except requests.RequestException as e:
        print(f"Error occurred: {e}")
    
    return None

def query_apk(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = set_headers()
    try:
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status()
            return response.json()
    
    except requests.HTTPError as e:
        handle_api_error(e)
    
    except requests.ConnectionError:
        print("Connection Error. Please check your network connection.")
    
    except requests.Timeout:
        print("Request Timed Out.")
    
    except requests.RequestException as e:
        print(f"Error occurred: {e}")