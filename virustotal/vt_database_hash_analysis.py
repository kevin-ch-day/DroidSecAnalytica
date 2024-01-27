
# vt_database_hash_analysis.py
from database import DBFunctions
from virustotal import vt_requests, vt_response

def run_analysis():
    apk_sample_records = DBFunctions.get_apk_samples()
    malware_hash_samples = DBFunctions.get_malware_hash_samples()

    for record in apk_sample_records:
        # Using file_name as the hash key for VirusTotal analysis
        hash_key = record['file_name']
        result = vt_requests.query_hash(hash_key)
        if result:
            vt_response.parse_response(result)

        # Handling the response from VirusTotal
        vt_analysis_result = vt_response.parse_response(vt_response)

        # Extracting hash values and the VirusTotal link from the response
        md5 = vt_analysis_result.get('md5')
        sha1 = vt_analysis_result.get('sha1')
        sha256 = vt_analysis_result.get('sha256')
        vt_link = vt_analysis_result.get('permalink')



if __name__ == '__main__':
    run_analysis()
