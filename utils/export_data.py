import json
import logging
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
from sklearn.cluster import KMeans

from utils import app_utils
from database import DBConnectionManager

def hash_data_excel():
    filename = 'output/android_hash_data.xlsx'
    print("Starting Excel export...")
    try:
        with DBConnectionManager.connect_to_database() as conn:
            print("Connected to the database. Exporting data to Excel...")
            sql = "SELECT * FROM android_malware_hashes"
            df = pd.read_sql(sql, conn)
            df.to_excel(filename, index=False)
            print(f"Data successfully exported to Excel: {filename}")
    except Exception as error:
        print(f"Error exporting data to Excel: {error}")

def hash_data_csv():
    filename = 'output/android_hash_data.csv'
    print("Starting CSV export...")
    try:
        with DBConnectionManager.connect_to_database() as conn:
            print("Connected to the database. Exporting data to CSV...")
            query = "SELECT * FROM android_malware_hashes"
            df = pd.read_sql(query, conn)
            df.to_csv(filename, index=False)
            print(f"Data successfully exported to CSV: {filename}")
    except Exception as error:
        print(f"Error exporting data to CSV: {error}")

def hash_data_txt():
    filename = 'output/android_malware_data.txt'
    print("Starting data export to TXT file...")
    try:
        conn = DBConnectionManager.connect_to_database()
        print("Connected to database. Retrieving data...")
        cursor = conn.cursor()
        sql = "SELECT * FROM android_malware_hashes"
        cursor.execute(sql)
        rows = cursor.fetchall()

        if rows:
            headers = [i[0] for i in cursor.description]  # Extracting column headers
            max_lengths = [len(str(max([str(row[i]) for row in rows], key=len))) for i in range(len(headers))]
            headers_line = ' | '.join([headers[i].ljust(max_lengths[i]) for i in range(len(headers))])
            app_utils.write_data_to_file(filename, headers_line, max_lengths, rows)
            print(f"Data successfully written to TXT file: {filename}")
        else:
            print("No data found in the database to export.")

        DBConnectionManager.close_database_connection(conn)
    except Exception as error:
        print(f"Error writing data to TXT file: {error}")

def save_top_hashes(cursor):
    filename = 'output/hash_analysis.txt'
    print("Generating top hash analysis...")
    try:
        with open(filename, 'a') as analysis_file:
            analysis_file.write("\nTop 10 Most Common Hashes:\n")
            app_utils.write_top_hashes("MD5 Hashes", analysis_file, cursor, "md5")
            app_utils.write_top_hashes("SHA1 Hashes", analysis_file, cursor, "sha1")
            app_utils.write_top_hashes("SHA256 Hashes", analysis_file, cursor, "sha256")
            print(f"Top hashes analysis written to {filename}")
    except IOError as error:
        print(f"Error writing analysis to file: {error}")

def write_total_entries(cursor, file):
    print("Fetching total entries...")
    sql = "SELECT COUNT(*) FROM android_malware_hashes"
    cursor.execute(sql)
    total_entries = cursor.fetchone()[0]
    file.write(f"Total Entries: {total_entries}\n\n")

def write_category_analysis(cursor, file):
    """ Write the analysis of data by malware categories to the provided file. """
    print("Analyzing data by category...")
    sql = "SELECT malware_name_1, COUNT(*) FROM android_malware_hashes GROUP BY malware_name_1"
    cursor.execute(sql)
    category_counts = cursor.fetchall()

    if not category_counts:
        file.write("No category data available.\n\n")
        return

    for category, count in category_counts:
        file.write(f"**{category}**\n")
        file.write(f"Category Count: {count} entries\n")

        # Analyze similarities within malware categories
        similar_categories = app_utils.find_similar_categories(category, category_counts)
        file.write("Similar Categories: ")
        file.write(", ".join(similar_categories) if similar_categories else "None")
        file.write("\n\n")

def write_year_month_analysis(cursor, file):
    """ Write the analysis of data by year and month to the provided file. """
    print("Analyzing data by year and month...")
    sql = "SELECT year, month, COUNT(*) FROM android_malware_hashes GROUP BY year, month"
    cursor.execute(sql)
    year_month_counts = cursor.fetchall()

    if not year_month_counts:
        file.write("No year-month data available.\n\n")
        return

    file.write("Malware Entries by Year and Month:\n")
    for year, month, count in year_month_counts:
        year_str = f"Year: {year}" if year else "Year: Unknown"
        month_str = f"Month: {month}" if month else "Month: Unknown"
        file.write(f"{year_str}, {month_str}, Count: {count}\n")
    file.write("\n")

def write_category_analysis(cursor, file):
    print("Analyzing data by primary and secondary categories...")
    
    # Advanced Analysis for malware_name_1
    file.write("Primary Category Advanced Analysis:\n")
    advanced_category_analysis(cursor, file, 'malware_name_1')

    # Advanced Analysis for malware_name_2
    file.write("\nSecondary Category Advanced Analysis:\n")
    advanced_category_analysis(cursor, file, 'malware_name_2')

    # Combined Analysis of both categories
    file.write("\nCombined Category Advanced Analysis:\n")
    write_combined_category_data(cursor, file)

def write_combined_category_data(cursor, file):
    """ Advanced analysis of combined category data. """
    sql = """
        SELECT malware_name_1, malware_name_2, COUNT(*) 
        FROM android_malware_hashes 
        GROUP BY malware_name_1, malware_name_2
    """
    cursor.execute(sql)
    combined_counts = cursor.fetchall()

    if not combined_counts:
        file.write("No combined category data available.\n\n")
        return

    # Advanced Analysis: Cross-category comparison, correlation analysis, etc.
    for name1, name2, count in combined_counts:
        name1_str = name1 if name1 else "Unknown"
        name2_str = name2 if name2 else "Unknown"
        file.write(f"Primary: **{name1_str}**, Secondary: **{name2_str}**, Count: {count}\n")
    
    
def write_combined_category_data(cursor, file):
    """ Advanced analysis of combined category data with clustering. """
    sql = """
        SELECT malware_name_1, malware_name_2, COUNT(*) 
        FROM android_malware_hashes 
        GROUP BY malware_name_1, malware_name_2
    """
    cursor.execute(sql)
    combined_data = cursor.fetchall()

    if not combined_data:
        file.write("No combined category data available.\n\n")
        return

    # Clustering for Cross-Category Insights
    df_combined = pd.DataFrame(combined_data, columns=['Name1', 'Name2', 'Count'])
    cluster_insights(df_combined)

    # Writing combined category analysis
    for name1, name2, count in combined_data:
        file.write(f"Primary: **{name1 if name1 else 'Unknown'}**, Secondary: **{name2 if name2 else 'Unknown'}**, Count: {count}\n")


# Function to write JSON data to a file
def write_json_to_file(filename, data):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)
    print(f"Data written to file: {filename}")

# Save the static scan results
def save_static_results(apk_basename, manifest_data, manifest_element):
    file_path = 'output/static_analysis_results.txt'
    try:
        with open(file_path, "w") as f:
            f.write(f"Static Analysis Results\n")
            f.write(f"APK: {apk_basename}\n")
            f.write("=" * 60 + "\n\n")

            write_manifest_data(f, manifest_data)
            write_manifest_element_data(f, manifest_element)

        logging.info(f"Static analysis results saved to {file_path}")

    except Exception as e:
        logging.error(f"Error saving analysis results: {e}")

def write_manifest_data(file, manifest_data):
    file.write("Manifest Data:\n")
    file.write("-" * 60 + "\n")
    for element, metadata_list in manifest_data.items():
        file.write(f"  {element.capitalize()}:\n")
        for index, metadata_item in enumerate(metadata_list, start=1):
            file.write(f"    [{index}] Name: {metadata_item['name']}\n")
        file.write("\n")

def write_manifest_element_data(file, manifest_element):
    file.write("Manifest Element Data:\n")
    file.write("-" * 60 + "\n")
    for attribute, value in manifest_element.items():
        if value:
            description = get_manifest_attribute_description(attribute)
            file.write(f"  {attribute}:\n")
            file.write(f"    Value: {value}\n")
            file.write(f"    Description: {description}\n\n")

def get_manifest_attribute_description(attribute):
    attribute_description = {
        "package": "The name of the package",
        "compileSdkVersion": "The compile SDK version",
        "compileSdkVersionCodename": "The compile SDK version codename",
        "platformBuildVersionCode": "The platform build version code",
        "platformBuildVersionName": "The platform build version name",
        "targetSdkVersion": "The target SDK version",
        "versionCode": "The version code",
        "versionName": "The version name",
        "installLocation": "The install location",
        "debuggable": "Whether the app is debuggable",
        "applicationLabel": "The application label",
        "packageInstaller": "The package installer",
    }
    return attribute_description.get(attribute, "No description available")