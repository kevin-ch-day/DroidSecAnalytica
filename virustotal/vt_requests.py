import requests
import logging
import time
from . import vt_config

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def set_headers():
    return {"x-apikey": vt_config.API_KEY}

def handle_api_error(e):
    logging.error(f"HTTP Error: {e.response.status_code} - {e.response.reason}")
    if e.response.content:
        logging.error("Error details: %s", e.response.content.decode())

def print_connection_issues(e):
    logging.error("Network Issue: %s", e)

def simple_retry_request(method, url, **kwargs):
    """A simple retry mechanism for HTTP requests."""
    max_retries = 3
    retry_delay = 1  # seconds
    for attempt in range(max_retries):
        try:
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                logging.warning("Request failed, retrying... Attempt %d of %d", attempt + 1, max_retries)
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                raise e  # Reraise the exception if all retries fail

def query_hash(hash_value):
    logging.info("Querying VirusTotal for hash: %s", hash_value)
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    try:
        response = simple_retry_request("GET", url, headers=set_headers())
        logging.info("Query successful.")
        return response.json()
    except requests.HTTPError as e:
        handle_api_error(e)
    except requests.ConnectionError as e:
        print_connection_issues(e)
    except requests.Timeout:
        logging.warning("Request Timed Out.")
    except requests.RequestException as e:
        logging.error("Unexpected Error: %s", e)
    return None

def query_apk(file_path):
    logging.info("Uploading APK for analysis: %s", file_path)
    url = "https://www.virustotal.com/api/v3/files"
    try:
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            response = simple_retry_request("POST", url, headers=set_headers(), files=files)
            logging.info("Upload and query successful.")
            return response.json()
    except requests.HTTPError as e:
        handle_api_error(e)
    except requests.ConnectionError as e:
        print_connection_issues(e)
    except requests.Timeout:
        logging.warning("Request Timed Out.")
    except requests.RequestException as e:
        logging.error("Unexpected Error: %s", e)
