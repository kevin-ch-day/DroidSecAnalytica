import requests
import json

API_KEY = '9665abbb72d64b0eae5b6fcc13db35c6139069fb1f9ae9db0824ba256e354a01'

def fetch_virustotal_report(file_hash):
    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': API_KEY, 'resource': file_hash}
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            result = response.json()
            
            if result['response_code'] == 1:
                return result
            elif result['response_code'] == 0:
                return {'error': 'No information available for this hash.'}
            else:
                return {'error': 'Error occurred during the scan.'}
        else:
            return {'error': 'Failed to connect to VirusTotal API.'}
    except Exception as e:
        return {'error': str(e)}

def save_report_to_file(file_hash, report_data):
    try:
        with open(f'{file_hash}_virustotal_report.json', 'w') as file:
            json.dump(report_data, file, indent=4)
    except IOError as e:
        return {'error': f'Error writing file: {e}'}
    return None

def main():
    hash = '9fa1e4b615d69f04da261267331a202b'
    result = fetch_virustotal_report(hash)
    print(result)
    exit()

    if 'error' in result:
        print(f"Error: {result['error']}")
    else:
        save_error = save_report_to_file(hash, result)
        if save_error is not None:
            print(f"Error saving report to file: {save_error}")
        else:
            print("Report saved successfully.")

if __name__ == "__main__":
    main()
