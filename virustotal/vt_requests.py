import time
import requests
from database import db_api_management
from utils import logging_utils

logger = logging_utils.get_logger(__name__)

# Constants
BASE_URL = "https://www.virustotal.com/api/v3/files"
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

def get_available_api_key():
    """Retrieve an available API key from the database."""
    api_key_data = db_api_management.get_available_api_key()
    if not api_key_data or "api_key" not in api_key_data:
        logger.warning("No API keys available.")
        return None, None
    return api_key_data["api_key"], api_key_data["id"]

def set_headers():
    """Return request headers and associated API key ID."""
    api_key, api_key_id = get_available_api_key()
    if not api_key:
        logger.error("No available API keys found.")
        return None, None
    headers = {"x-apikey": api_key}
    return headers, api_key_id

def https_request(method, url, headers=None, files=None):
    """Perform an HTTP request with retry logic."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.debug("Attempt %d: %s %s", attempt, method, url)
            response = requests.request(method, url, headers=headers, files=files)
            if response.status_code == 401:
                logger.warning(
                    "API key ending in %s is invalid.", headers["x-apikey"][-8:]
                )
                return "INVALID_API_KEY"
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            status = response.status_code if "response" in locals() else "Unknown"
            logger.warning("HTTP Error (%s): %s", status, e)
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error: %s", e)
        except requests.exceptions.Timeout:
            logger.error("Request timed out.")
        except requests.exceptions.RequestException as e:
            logger.error("Unexpected error: %s", e)
        time.sleep(RETRY_DELAY)
    logger.error("Max retries reached. Request failed.")
    return None

def check_all_api_keys():
    """Verify that all stored API keys are working."""
    all_keys = db_api_management.get_virustotal_api_keys()
    failed_keys = []
    valid_keys = []
    test_url = "https://www.virustotal.com/api/v3/users/me"

    logger.info("Checking validity of all VirusTotal API keys...")
    for api_key in all_keys:
        headers = {"x-apikey": api_key}
        try:
            response = requests.get(test_url, headers=headers, timeout=5)
            if response.status_code == 401:
                failed_keys.append(api_key[-8:])
                logger.warning("API Key ending in %s is INVALID.", api_key[-8:])
            elif response.status_code == 200:
                valid_keys.append(api_key[-8:])
                logger.info("API Key ending in %s is VALID.", api_key[-8:])
        except requests.exceptions.ConnectionError:
            logger.error("Could not connect to VirusTotal.")
            return False
        except requests.exceptions.Timeout:
            logger.error("Request to VirusTotal timed out.")
            return False
    if not valid_keys:
        logger.critical("No valid API keys found. Please update your keys.")
        return False
    return True

def get_request_details(data, query_type, headers):
    """Determine request URL, method, and file payload based on the query type."""
    if query_type == "hash":
        logger.debug("Hash query using API key ending in %s", headers["x-apikey"][-8:])
        return f"{BASE_URL}/{data}", "GET", None
    elif query_type == "apk":
        logger.debug("Uploading APK with API key ending in %s", headers["x-apikey"][-8:])
        try:
            with open(data, "rb") as file:
                return BASE_URL, "POST", {"file": (data, file)}
        except FileNotFoundError:
            logger.error("File '%s' not found.", data)
            return None, None, None

def handle_invalid_api_key(headers, failed_keys):
    """Mark an invalid API key and verify remaining keys."""
    failed_keys.add(headers["x-apikey"])
    logger.warning(
        "API key ending in %s is invalid. Checking all API keys.",
        headers["x-apikey"][-8:]
    )
    if not check_all_api_keys():
        logger.critical("No working API keys available.")
        return False
    return True

def process_response(response, api_key_id, data, query_type):
    """Update key usage and parse the JSON response."""
    if response is None:
        logger.error("Query failed for %s: %s", query_type, data)
        return None
    db_api_management.update_api_key_usage(api_key_id)
    try:
        return response.json()
    except ValueError:
        logger.error("Failed to decode JSON for %s", data)
        return None

def query_virustotal(data, query_type):
    """Handle VirusTotal hash queries and APK uploads."""
    failed_keys = set()
    while True:
        headers, api_key_id = set_headers()
        if not headers:
            logger.error("No valid API key. Checking all API keys.")
            if not check_all_api_keys():
                return None
            continue
        url, method, files = get_request_details(data, query_type, headers)
        if not url:
            return None
        response = https_request(method, url, headers=headers, files=files)
        if response == "INVALID_API_KEY":
            if not handle_invalid_api_key(headers, failed_keys):
                return None
            continue
        return process_response(response, api_key_id, data, query_type)
