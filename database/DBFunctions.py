from typing import Dict
from utils import logging_utils
from . import DBConnectionManager as dbConnect

def get_apk_samples():
    query = "SELECT * FROM apk_samples"
    return dbConnect.execute_query(query, fetch=True)

def get_malware_hash_samples():
    query = "SELECT * FROM malware_hashes"
    return dbConnect.execute_query(query, fetch=True)