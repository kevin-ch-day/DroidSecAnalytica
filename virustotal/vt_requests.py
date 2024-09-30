import requests
import time
from db_operations import db_vt_api_keys

# Constants
BASE_URL = "https://www.virustotal.com/api/v3/files"
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

# Function: get_available_api_key
# Retrieves an available API key from the database and checks for stale keys.
def get_available_api_key():
    api_key_data = db_vt_api_keys.get_available_api_key()
    
    if not api_key_data:
        # If no available API key, check if reset is required
        print("[WARNING] No API keys available after reset check. Exiting.")
        return None, None
    
    api_key = api_key_data['api_key']
    api_key_id = api_key_data['id']
    return api_key, api_key_id

# Function: set_headers
# Sets the headers for the API request
def set_headers():
    api_key, api_key_id = get_available_api_key()
    if not api_key:
        print("[ERROR] No available API keys found.")
        return None, None

    headers = {
        "x-apikey": api_key
    }
    return headers, api_key_id

# Function: https_request
# This function performs the actual API request, handling retries and errors.
def https_request(method, url, headers=None, files=None):
    attempt = 0
    while attempt < MAX_RETRIES:
        try:
            response = requests.request(method, url, headers=headers, files=files)
            response.raise_for_status()  # Raise an error for HTTP error codes (4xx, 5xx)
            return response
        
        except requests.exceptions.HTTPError as e:
            print(f"[WARNING] API request failed (Attempt {attempt+1}/{MAX_RETRIES}): {e}")
            attempt += 1
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)  # Wait before retrying
            else:
                print("[ERROR] Max retries hit. Exiting...")
                return None
        
        except requests.exceptions.ConnectionError as e:
            print(f"[ERROR] Connection error: {e}")
            return None
        
        except requests.exceptions.Timeout:
            print(f"[ERROR] Request timed out.")
            return None

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Unexpected error: {e}")
            return None

# Function: handle_api_error
# This function handles API errors by printing the error code, reason, and additional details from the response.
def handle_api_error(e):
    print(f"[ERROR] HTTP Error occurred: {e.response.status_code} - {e.response.reason}")
    if e.response.content:
        print("[ERROR] Error details:", e.response.content.decode())

# Function: query_virustotal
# This function handles both file hash queries and APK file uploads to VirusTotal, processes the API response, and updates the API key usage.
def query_virustotal(data, query_type):
    headers, api_key_id = set_headers()
    if not headers:
        print("[ERROR] Could not retrieve a valid API key. Aborting the request.")
        return None

    if query_type == 'hash':
        print(f"\n[INFO] Initiating query for hash: {data}")
        url = f"{BASE_URL}/{data}"
        method = "GET"
        files = None
    
    elif query_type == 'apk':
        print(f"[INFO] Initiating APK upload for analysis: {data}")
        url = BASE_URL
        method = "POST"
        with open(data, 'rb') as file:
            files = {'file': (data, file)}

    try:
        response = https_request(method, url, headers=headers, files=files)
        
        if response is None:
            print(f"[ERROR] Query failed for {query_type}: {data}")
            return None

        # Update API key usage after successful request
        db_vt_api_keys.update_api_key_usage(api_key_id)
        return response.json()

    except requests.HTTPError as e:
        handle_api_error(e)
    except requests.ConnectionError as e:
        print("[ERROR] Network Issue encountered:", e)
    except requests.Timeout:
        print("[ERROR] Request timed out.")
    except requests.RequestException as e:
        print("[ERROR] Unexpected error occurred:", e)

    return None

# Function: reset_all_api_keys
# This function resets the request count for all API keys at the end of the day or as needed.
def reset_all_api_keys():
    print("[INFO] Resetting all API key request counts.")
    db_vt_api_keys.reset_api_key_usage()
