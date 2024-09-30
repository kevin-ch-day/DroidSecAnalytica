from db_operations import db_conn
import re

# Function to validate if a hash is a valid hexadecimal string of the correct length
def is_valid_hash(hash_value: str, hash_type: str) -> bool:
    hash_lengths = {
        "MD5": 32,
        "SHA1": 40,
        "SHA256": 64
    }
    return bool(re.fullmatch(r'[a-fA-F0-9]{' + str(hash_lengths[hash_type]) + '}', hash_value))

# Function to scan the hash_data_ioc table and check for duplicates, irregularities, and invalid hashes
def scan_hash_table():
    # Query to retrieve all records from hash_data_ioc
    query = "SELECT id, md5, sha1, sha256 FROM hash_data_ioc"
    
    try:
        # Execute the query and fetch all records
        records = db_conn.execute_query(query, fetch=True)

        if not records:
            print("\n[INFO] No records found in the 'hash_data_ioc' table.")
            return

        # Dictionaries to store unique hashes and detect duplicates
        md5_hashes = {}
        sha1_hashes = {}
        sha256_hashes = {}

        duplicates = []
        irregularities = []
        invalid_hashes = []

        print("\n========================================")
        print("  *** HASH DATA SCAN RESULTS ***")
        print("========================================")

        # Loop through all records to check for duplicates, irregularities, and invalid hashes
        for record in records:
            record_id, md5, sha1, sha256 = record

            # Check for duplicate MD5 hashes
            if md5:
                if not is_valid_hash(md5, "MD5"):
                    invalid_hashes.append((record_id, "MD5", md5))
                elif md5 in md5_hashes:
                    duplicates.append((record_id, "MD5", md5, md5_hashes[md5]))
                else:
                    md5_hashes[md5] = record_id

            # Check for duplicate SHA1 hashes
            if sha1:
                if not is_valid_hash(sha1, "SHA1"):
                    invalid_hashes.append((record_id, "SHA1", sha1))
                elif sha1 in sha1_hashes:
                    duplicates.append((record_id, "SHA1", sha1, sha1_hashes[sha1]))
                else:
                    sha1_hashes[sha1] = record_id

            # Check for duplicate SHA256 hashes
            if sha256:
                if not is_valid_hash(sha256, "SHA256"):
                    invalid_hashes.append((record_id, "SHA256", sha256))
                elif sha256 in sha256_hashes:
                    duplicates.append((record_id, "SHA256", sha256, sha256_hashes[sha256]))
                else:
                    sha256_hashes[sha256] = record_id

            # Check for records that do not have any valid hash
            if not (md5 or sha1 or sha256):
                irregularities.append(record_id)

        # Displaying results for duplicates
        if duplicates:
            print("\n[!] Duplicates Detected")
            print("-------------------------------------------------")
            print(f"{'Record ID':<10} | {'Hash Type':<10} | {'Duplicate Hash':<40} | {'Existing Record ID'}")
            print("-------------------------------------------------")
            for dup in duplicates:
                print(f"{dup[0]:<10} | {dup[1]:<10} | {dup[2]:<40} | {dup[3]}")
            print("-------------------------------------------------")
        else:
            print("\n[INFO] No duplicate hashes found.")

        # Displaying results for invalid hashes
        if invalid_hashes:
            print("\n[!] Invalid Hashes Detected")
            print("-------------------------------------------------")
            print(f"{'Record ID':<10} | {'Hash Type':<10} | {'Invalid Hash':<40}")
            print("-------------------------------------------------")
            for inv in invalid_hashes:
                print(f"{inv[0]:<10} | {inv[1]:<10} | {inv[2]:<40}")
            print("-------------------------------------------------")
        else:
            print("\n[INFO] No invalid hashes found.")

        # Displaying results for irregular records
        if irregularities:
            print("\n[!] Irregular Records Detected")
            print("-------------------------------------------------")
            print(f"{'Record ID':<10} | {'Status':<30}")
            print("-------------------------------------------------")
            for irr in irregularities:
                print(f"{irr:<10} | No valid MD5, SHA1, or SHA256 hashes")
            print("-------------------------------------------------")
        else:
            print("\n[INFO] No irregular records found.")

        # Final Summary
        print("\n========================================")
        print("  *** SCAN SUMMARY ***")
        print("========================================")
        print(f"Total records scanned:      {len(records)}")
        print(f"Total duplicates detected:  {len(duplicates)}")
        print(f"Total invalid hashes found: {len(invalid_hashes)}")
        print(f"Total irregular records:    {len(irregularities)}")
        print("========================================\n")

    except Exception as e:
        print(f"\n[ERROR] Failed to scan the 'hash_data_ioc' table: {e}")

# Main execution
if __name__ == "__main__":
    scan_hash_table()
