import requests
import json

# Hardcoded API key and hash (Replace with your own values)
API_KEY = "30c267c3babffbd22f7ffe6aa97b15d1f0a4f958c3db83431bc909a104b7f14f"
HASH_TO_CHECK = "4531126729cabd48c97bb1709dd59dc2"

# VirusTotal API Endpoint for hash lookup
VT_URL = f"https://www.virustotal.com/api/v3/files/{HASH_TO_CHECK}"

# Headers including the API key
HEADERS = {
    "x-apikey": API_KEY
}

def check_virustotal_hash():
    try:
        # Sending GET request to VirusTotal API
        response = requests.get(VT_URL, headers=HEADERS)
        
        # Checking for HTTP errors
        response.raise_for_status()
        
        # Parsing JSON response
        data = response.json()
        
        # Check if valid data is returned
        if "data" in data and "attributes" in data["data"]:
            attributes = data["data"]["attributes"]
            print("\n--- VirusTotal Hash Analysis ---")
            print(f"SHA256: {attributes.get('sha256', 'N/A')}")
            print(f"MD5: {attributes.get('md5', 'N/A')}")
            print(f"First Submission Date: {attributes.get('first_submission_date', 'N/A')}")
            print(f"Last Analysis Date: {attributes.get('last_analysis_date', 'N/A')}")
            
            # VirusTotal Detections Summary
            stats = attributes.get("last_analysis_stats", {})
            print("\n--- Detection Results ---")
            print(f"Malicious: {stats.get('malicious', 0)}")
            print(f"Suspicious: {stats.get('suspicious', 0)}")
            print(f"Undetected: {stats.get('undetected', 0)}")
            
            # List of antivirus detections
            if "last_analysis_results" in attributes:
                print("\n--- Antivirus Detections ---")
                for engine, result in attributes["last_analysis_results"].items():
                    if result["category"] in ["malicious", "suspicious"]:
                        print(f"{engine}: {result['result']}")
            
        else:
            print("No data available for the given hash.")
    
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP Error: {http_err}")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to VirusTotal. Check your internet connection.")
    except requests.exceptions.Timeout:
        print("Error: Request to VirusTotal timed out.")
    except requests.exceptions.RequestException as req_err:
        print(f"Request Error: {req_err}")
    except json.JSONDecodeError:
        print("Error: Unable to parse JSON response from VirusTotal.")

# Run the function
if __name__ == "__main__":
    check_virustotal_hash()
