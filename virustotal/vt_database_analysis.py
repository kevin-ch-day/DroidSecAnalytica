from utils import logging_utils
from database import DBFunctions
from . import vt_requests

def run_analysis():
    apk_sample_records = DBFunctions.get_apk_samples()
    malware_hash_samples = DBFunctions.get_malware_hash_samples()

    for record in apk_sample_records:
        # Using file_name as the hash key for VirusTotal analysis
        hash_key = record['file_name']
        result = vt_requests.query_hash(hash_key)
        if result:
            data = analyze_response(result)
            md5 = data.get('md5')
            sha1 = data.get('sha1')
            sha256 = data.get('sha256')
            vt_link = data.get('permalink')
