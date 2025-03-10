# report_data_func.py

import pandas as pd
from database import db_conn, db_permissions

def calculate_family_averages(df):
    # Prepare the data for calculations
    df_temp = df.copy()
    df_temp['%'] = df_temp['%'].str.rstrip('%').astype(float)
    malicious_counts = df['AV Detection'].str.split('/', expand=True)[0].astype(int)
    df_temp['Malicious'] = malicious_counts

    # Group by 'Family' and calculate averages
    family_avg_percentage = df_temp.groupby('Family')['%'].mean().reset_index(name='Avg % Family')
    family_avg_malicious = df_temp.groupby('Family')['Malicious'].mean().reset_index(name='Avg Malicious')

    # Merge the average percentage and malicious count DataFrames
    family_averages = pd.merge(family_avg_percentage, family_avg_malicious, on='Family')

    # Write the combined DataFrame to an Excel file
    averages_excel_path = "FamilyAverages.xlsx"
    family_averages.to_excel(averages_excel_path, index=False)
    print(f"Family averages written to {averages_excel_path} successfully.")

def write_andro_data_section(andro_data, file):
    """Writes the Android application data section to the file."""
    file.write("\nAndroid Application Data\n" + "=" * 50 + "\n")
    if andro_data:
        file.write(f"Package Name: {andro_data.get('package', 'N/A')}\n")
        file.write(f"Main Activity: {andro_data.get('main_activity', 'N/A')}\n")
        file.write(f"Target SDK Version: {andro_data.get('target_sdk_version', 'N/A')}\n")
        file.write(f"Minimum SDK Version: {andro_data.get('min_sdk_version', 'N/A')}\n")
        file.write(f"MD5 Hash: {andro_data.get('md5', 'N/A')}\n")
        file.write(f"SHA1 Hash: {andro_data.get('sha1', 'N/A')}\n")
        file.write(f"SHA256 Hash: {andro_data.get('sha256', 'N/A')}\n")
    else:
        file.write("No Android application data available.\n")

def analyze_known_permissions():
    try:
        # Fetch data from the database using the known permissions query
        print("\nFetching data for known permissions analysis...")

        KNOWN_PERMISSIONS_QUERY = """
        SELECT DISTINCT y.permission_name, 
                        y.constant_value, 
                        y.protection_level, 
                        y.andro_type,
                        CASE
                            WHEN y.protection_level LIKE '%dangerous%' OR y.andro_type LIKE '%Dangerous%' THEN 'High Risk'
                            WHEN y.protection_level LIKE '%normal%' THEN 'Low Risk'
                            ELSE 'Medium Risk'
                        END AS risk_category
        FROM vt_permissions x
        JOIN android_permissions y ON y.permission_id = x.known_permission_id
        WHERE x.known_permission_id IS NOT NULL
        ORDER BY risk_category, y.permission_name;
        """

        df = db_conn.generate_df_from_query(KNOWN_PERMISSIONS_QUERY)
        if df is None:
            return None
        
        # Perform data analysis
        print("Performing data analysis for known permissions...")
        #print(df)
        total_known_permissions = len(df)
        #risk_category_counts = df['risk_category'].value_counts()
        risk_category_counts = df[4].value_counts()
        risk_category_percentages = (risk_category_counts / total_known_permissions) * 100

        # Prepare the analysis result as a dictionary
        analysis_result = {
            'total_known_permissions': total_known_permissions,
            'risk_category_counts': risk_category_counts,
            'risk_category_percentages': risk_category_percentages
        }

        return analysis_result
    
    except Exception as e:
        print(f"An error occurred during known permissions analysis: {str(e)}")
        return None

def analyze_unknown_permissions():
    try:
        # Fetch data from the database using the unknown permissions query
        print("\nFetching data for unknown permissions analysis...")

        UNKNOWN_PERMISSIONS_QUERY = """
        SELECT DISTINCT x.unknown_permission_id,
            y.constant_value,
            y.andro_type,
            CASE
                WHEN y.andro_type LIKE '%Dangerous%' THEN 'High Risk'
                WHEN y.andro_type LIKE '%Normal%' THEN 'Low Risk'
                ELSE 'Medium Risk'
            END AS risk_assessment
        FROM vt_permissions x
        JOIN android_permissions_unknown y ON y.permission_id = x.unknown_permission_id
        WHERE x.unknown_permission_id IS NOT NULL
        ORDER BY y.constant_value;
        """

        df = db_conn.generate_df_from_query(UNKNOWN_PERMISSIONS_QUERY)
        if df is None:
            return None

        # Perform data analysis
        print("Performing data analysis for unknown permissions...")
        total_unknown_permissions = len(df)
        #risk_assessment_counts = df['risk_assessment'].value_counts()
        risk_assessment_counts = df[4].value_counts()
        total_permissions = total_unknown_permissions + risk_assessment_counts.sum()
        risk_assessment_percentages = (risk_assessment_counts / total_permissions) * 100

        # Prepare the analysis result as a dictionary
        analysis_result = {
            'total_unknown_permissions': total_unknown_permissions,
            'risk_assessment_counts': risk_assessment_counts,
            'risk_assessment_percentages': risk_assessment_percentages
        }

        return analysis_result
    
    except Exception as e:
        print(f"An error occurred during unknown permissions analysis: {str(e)}")
        return None
    
def fetch_and_analyze_permissions(md5_hashes):
    permissions_data = db_permissions.fetch_apk_permissions(md5_hashes)
    if not permissions_data:
        print("No permissions data fetched for the provided MD5 hashes.")
        exit()
    
    return pd.DataFrame(permissions_data, columns=['APK ID', 'Perm Name', 'Protection Level'])

def analyze_distribution(df):
    return df['Perm Name'].value_counts()

def analyze_protection_counts(df):
    return df['Protection Level'].value_counts()

def find_unique_permissions(df):
    return df.drop_duplicates(subset=['Perm Name'])

def find_common_permissions(df):
    return df.groupby('Perm Name').filter(lambda x: len(x) > 1)

def generate_permission_matrices_by_level(df):
    writer = pd.ExcelWriter('output/permissions_by_level.xlsx', engine='xlsxwriter')
    
    for level in ['dangerous', 'normal', 'signature']:
        level_df = df[df['Protection Level'] == level]
        if not level_df.empty:
            pivot_table = level_df.pivot_table(index='Perm Name', columns='APK ID', aggfunc='size')
            pivot_table.to_excel(writer, sheet_name=level.capitalize())
    
    writer.close()
    print("Pivot tables for each protection level have been saved.")
