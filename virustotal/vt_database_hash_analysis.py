# vt_database_hash_analysis.py
from database import DBFunctions

def run_analysis():
    apk_sample_records = DBFunctions.get_apk_samples()
    malware_hash_samples = DBFunctions.get_malware_hash_samples()