from . import db_conn_v2 as db_conn
import pandas as pd

def fetch_overall_vt_detection():
    sql = """
    SELECT am.analysis_id AS 'ID',
        ms.name_2 AS 'Family',
        am.sample_classification AS DroidSecAnalytica,
        sa.Kaspersky,
        DATE_FORMAT(ms.vt_first_submission, '%m-%d-%Y') AS 'First Submission',
        sa.malicious 'Malicious',
        (sa.malicious + sa.undetected) AS 'Total AV',
        (sa.malicious / (sa.malicious + sa.undetected)) * 100 AS '%'
    FROM analysis_metadata AS am
    JOIN malware_samples AS ms ON ms.sha256 = am.sha256
    JOIN vt_scan_analysis AS sa ON am.analysis_id = sa.analysis_id
    ORDER BY sa.malicious DESC
    """

    results = db_conn.execute_query(sql, fetch=True)
    if not results:
        print("No data returned from the query.")
        return
    return results

def top_permissions(data, protection_level):
    try:
        if data is not None:
            top_permissions_query = """
            SELECT ap.permission_name 'Permission',
                COUNT(DISTINCT am.analysis_id) AS 'Found',
                COUNT(DISTINCT am.analysis_id) * 100.0 / (SELECT COUNT(DISTINCT analysis_id) FROM analysis_metadata WHERE ap.protection_level = '{}') AS '%'
            FROM analysis_metadata AS am
                JOIN malware_samples AS ms
                    ON ms.sha256 = am.sha256_hash
                JOIN vt_permissions vtp
                    ON vtp.apk_id = ms.id
                JOIN android_permissions ap
                    ON ap.permission_id = vtp.known_permission_id
            WHERE ap.protection_level = '{}'
            GROUP BY ap.permission_name
            ORDER BY COUNT(DISTINCT am.analysis_id) DESC
            LIMIT 10
            """.format(protection_level, protection_level)
            results = db_conn.execute_query(top_permissions_query, fetch=True)
            
            if not results:
                print(f"No {protection_level} data found matching the criteria.")
                return None

            df = pd.DataFrame(results)
            print(f"\nTop {protection_level} protection level permissions:")
            print(df)
            return df
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
def fetch_permissions_data(protection_level):
    try:
        query = """
        SELECT 
            am.analysis_id AS 'ID',
            ms.name_2 AS 'Family',
            am.sample_classification AS 'DroidSecAnalytica',
            vtp.known_permission_id AS 'Permission ID',
            ap.permission_name AS 'Permission name'
        FROM 
            analysis_metadata AS am
        JOIN 
            malware_samples AS ms ON ms.sha256 = am.sha256_hash
        JOIN 
            vt_permissions AS vtp ON vtp.apk_id = ms.id
        JOIN 
            android_permissions AS ap ON ap.permission_id = vtp.known_permission_id
        WHERE 
            ap.permission_name IN (
                'SYSTEM_ALERT_WINDOW',
                'INTERNET',
                'ACCESS_NETWORK_STATE',
                'READ_PHONE_STATE',
                'READ_SMS',
                'RECEIVE_SMS',
                'READ_CONTACTS',
                'WRITE_EXTERNAL_STORAGE'
            );
        """
        results = db_conn.execute_query(query, fetch=True)
        
        if not results:
            print("No data found matching the criteria.")
            return None

        return pd.DataFrame(results)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def fetch_overlay_permissions_data():
    try:
        query = """
        SELECT 
            am.analysis_id AS 'ID',
            ms.name_2 AS 'Family',
            am.sample_classification AS 'DroidSecAnalytica',
            vtp.known_permission_id AS 'Permission ID',
            ap.permission_name AS 'Permission name'
        FROM 
            analysis_metadata AS am
        JOIN 
            malware_samples AS ms ON ms.sha256 = am.sha256_hash
        JOIN 
            vt_permissions AS vtp ON vtp.apk_id = ms.id
        JOIN 
            android_permissions AS ap ON ap.permission_id = vtp.known_permission_id
        WHERE 
            ap.permission_name IN (
                'SYSTEM_ALERT_WINDOW',
                'INTERNET',
                'ACCESS_NETWORK_STATE',
                'READ_PHONE_STATE',
                'READ_SMS',
                'RECEIVE_SMS',
                'READ_CONTACTS',
                'WRITE_EXTERNAL_STORAGE'
            );
        """
        results = db_conn.execute_query(query, fetch=True)
        
        if not results:
            print("No data found matching the criteria.")
            return None

        return pd.DataFrame(results)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None