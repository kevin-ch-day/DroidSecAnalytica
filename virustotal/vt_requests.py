import requests
import time
import json
import datetime
from db_operations import db_vt_api_keys

# Constants
BASE_URL = "https://www.virustotal.com/api/v3/files"
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

def log_event(message):
    """Helper function to log timestamped messages."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def get_available_api_key():
    """
    Retrieves an available API key from the database and checks for stale keys.
    If no API key is available, it returns None.
    """
    api_key_data = db_vt_api_keys.get_available_api_key()
    
    if not api_key_data or 'api_key' not in api_key_data:
        log_event("[WARNING] No API keys available. Exiting.")
        return None, None
    
    return api_key_data['api_key'], api_key_data['id']

def set_headers():
    """
    Sets the headers for the API request by retrieving a valid API key.
    Returns headers and API key ID.
    """
    api_key, api_key_id = get_available_api_key()
    if not api_key:
        log_event("[ERROR] No available API keys found.")
        return None, None

    headers = {"x-apikey": api_key}
    return headers, api_key_id

def https_request(method, url, headers=None, files=None):
    """
    Handles API requests with retry logic.
    Automatically switches API keys on a 401 Unauthorized error.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.request(method, url, headers=headers, files=files)
            if response == "<Response [401]>":
                print(f"[WARNING] API key ending in {headers['x-apikey'][-8:]} is invalid. Trying another key.")
                return "INVALID_API_KEY"  # Signal to switch API keys

            return response  # Successfully received response
        
        except requests.exceptions.HTTPError as e:
            status_code = response.status_code if response else "Unknown"
            print(f"[WARNING] HTTP Error ({status_code}): {e}")
            return None

        except requests.exceptions.ConnectionError as e:
            print(f"[ERROR] Connection error: {e}")
            return None
        
        except requests.exceptions.Timeout:
            print("[ERROR] Request timed out.")
            return None

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Unexpected error: {e}")
            return None

        print(f"[INFO] Retrying ({attempt}/{MAX_RETRIES}) in {RETRY_DELAY} seconds...")
        time.sleep(RETRY_DELAY)
    
    print("[ERROR] Max retries reached. Request failed.")
    return None

def check_all_api_keys():
    """
    Verifies that all API keys are working.
    If all fail, alerts the user.
    """
    all_keys = db_vt_api_keys.get_all_api_keys()
    failed_keys = []
    valid_keys = []
    test_url = "https://www.virustotal.com/api/v3/users/me"  # Test endpoint

    print("\n[INFO] Checking the validity of all VirusTotal API keys...\n")

    for api_key in all_keys:
        headers = {"x-apikey": api_key}
        try:
            response = requests.get(test_url, headers=headers, timeout=5)

            if response.status_code == 401:
                failed_keys.append(api_key[-8:])
                print(f"[WARNING] API Key ending in {api_key[-8:]} is INVALID.")

            elif response.status_code == 200:
                valid_keys.append(api_key[-8:])
                print(f"[SUCCESS] API Key ending in {api_key[-8:]} is VALID.")

        except requests.exceptions.ConnectionError:
            print("[ERROR] Could not connect to VirusTotal. Check network.")
            return False
        
        except requests.exceptions.Timeout:
            print("[ERROR] Request to VirusTotal timed out.")
            return False

    if not valid_keys:
        print("[CRITICAL] No valid API keys found. Please update your keys.")
        return False
    return True


def get_request_details(data, query_type, headers):
    """
    Determines the request URL, method, and file data based on the query type.
    """
    if query_type == 'hash':
        log_event(f"\nHash: {data}")
        log_event(f"API key ending in {headers['x-apikey'][-8:]}\n")
        return f"{BASE_URL}/{data}", "GET", None

    elif query_type == 'apk':
        log_event(f"Uploading APK with API key ending in {headers['x-apikey'][-8:]}")
        try:
            with open(data, 'rb') as file:
                return BASE_URL, "POST", {'file': (data, file)}
        except FileNotFoundError:
            log_event(f"[ERROR] File '{data}' not found.")
            return None, None, None

def handle_invalid_api_key(headers, failed_keys):
    """
    Handles an invalid API key by marking it as bad and checking for valid keys.
    """
    failed_keys.add(headers["x-apikey"])  # Mark API key as bad
    log_event(f"[WARNING] API key ending in {headers['x-apikey'][-8:]} is invalid. Checking all API keys.")

    if not check_all_api_keys():
        log_event("[CRITICAL] No working API keys available. Exiting.")
        return False  # No valid keys left, exit the program
    return True  # Retry with a new API key

def process_response(response, api_key_id, data, query_type):
    """
    Processes the response, updates API key usage, and returns parsed JSON data.
    """
    if response is None:
        log_event(f"[ERROR] Query failed for {query_type}: {data}")
        return None

    # Update API key usage after a successful request
    db_vt_api_keys.update_api_key_usage(api_key_id)
    return response.json()

def query_virustotal(data, query_type):
    """
    Handles VirusTotal hash queries and APK uploads.
    Ensures API key validation and rotates keys if needed.
    """
    failed_keys = set()

    while True:
        headers, api_key_id = set_headers()
        if not headers:
            print("[ERROR] No valid API key. Checking all API keys.")
            if not check_all_api_keys():
                return None
            continue  

        url, method, files = get_request_details(data, query_type, headers)

        response = https_request(method, url, headers=headers, files=files)

        if response == "INVALID_API_KEY":
            if not handle_invalid_api_key(headers, failed_keys):
                return None  # No valid API keys left, exit
            continue  

        return process_response(response, api_key_id, data, query_type)

def reset_all_api_keys():
    """
    Resets the request count for all API keys at the end of the day or as needed.
    """
    log_event("[INFO] Resetting all API key request counts.")
    db_vt_api_keys.reset_api_key_usage()
