import requests

api_key = '9665abbb72d64b0eae5b6fcc13db35c6139069fb1f9ae9db0824ba256e354a01'

def fetch_virustotal_report(file_hash):
    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api_key, 'resource': file_hash}
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