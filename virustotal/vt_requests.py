import requests

API_KEY = '30c267c3babffbd22f7ffe6aa97b15d1f0a4f958c3db83431bc909a104b7f14f'

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