import logging
import pandas as pd
from utils import app_utils

from database import DBConnectionManager

def android_hash_data_to_excel():
    filename = 'output/android_hash_data.xlsx'
    try:
        with DBConnectionManager.connect_to_database() as conn:
            sql = "SELECT * FROM android_malware_hashes"
            df = pd.read_sql(sql, conn)
            df.to_excel(filename, index=False)
            print(f"Data successfully exported to {filename}")
    except Exception as error:
        logging.error(f"Error exporting data to Excel: {error}")

def android_hash_data_to_csv():
    filename = 'output/android_hash_data.csv'
    try:
        with DBConnectionManager.connect_to_database() as conn:
            query = "SELECT * FROM android_malware_hashes"
            df = pd.read_sql(query, conn)
            df.to_csv(filename, index=False)
            print(f"Data successfully exported to {filename}")
    except Exception as error:
        logging.error(f"Error exporting data to CSV: {error}")

def save_top_hashes(cursor):
    filename = 'output/hash_analysis.txt'
    conn = DBConnectionManager.connect_to_database()
    cursor = conn.cursor()

    try:
        with open(filename, 'a') as analysis_file:
            analysis_file.write("\nTop 10 Most Common Hashes:\n")
            app_utils.write_top_hashes("MD5 Hashes", analysis_file, cursor, "md5")
            app_utils.write_top_hashes("SHA1 Hashes", analysis_file, cursor, "sha1")
            app_utils.write_top_hashes("SHA256 Hashes", analysis_file, cursor, "sha256")
            analysis_file.write("\nAdditional Analysis:\n")

            # Count of unique locations
            sql = "SELECT COUNT(DISTINCT location) FROM android_malware_hashes"
            unique_locations = DBConnectionManager.execute_sql(cursor, sql)
            unique_locations = unique_locations[0][0]
            analysis_file.write(f"Unique Locations: {unique_locations}\n")

            # Count of unique months
            sql = "SELECT COUNT(DISTINCT month) FROM android_malware_hashes"
            unique_months = DBConnectionManager.execute_sql(cursor, sql)
            unique_months = unique_months[0][0]
            analysis_file.write(f"Unique Months: {unique_months}\n")

            # Finding and fixing bad data
            sql = "SELECT COUNT(*) FROM android_malware_hashes WHERE malware_category IS NULL OR location IS NULL OR month IS NULL"
            null_data_count = DBConnectionManager.execute_sql(cursor, sql)
            null_data_count = null_data_count[0][0]
            analysis_file.write(f"Entries with Missing Data: {null_data_count}\n")

            sql = "SELECT COUNT(*) FROM android_malware_hashes WHERE malware_category = '' OR location = '' OR month = ''"
            empty_data_count = DBConnectionManager.execute_sql(cursor, sql)
            empty_data_count = empty_data_count[0][0]
            analysis_file.write(f"Entries with Empty Data: {empty_data_count}\n")

            # Count of entries per malware category
            sql = "SELECT malware_category, COUNT(*) FROM android_malware_hashes GROUP BY malware_category"
            category_counts = DBConnectionManager.execute_sql(cursor, sql)
            analysis_file.write("\nMalware Category Analysis:\n")
            for category, count in category_counts:
                analysis_file.write(f" '{category}': {count} entries\n")

            # Count of entries per month
            sql = "SELECT month, COUNT(*) FROM android_malware_hashes GROUP BY month"
            month_counts = DBConnectionManager.execute_sql(cursor, sql)
            analysis_file.write("\nMonthly Analysis:\n")
            for month, count in month_counts:
                analysis_file.write(f" {month}: {count} entries\n")

            print(f"Analysis successfully written to {filename}")

        DBConnectionManager.close_database_connection(conn)

    except IOError as error:
        logging.error(f"Error writing analysis to file: {error}")

def write_analysis_to_file(cursor):
    filename = 'output/analysis.txt'
    try:
        with open(filename, 'w') as f:
            f.write('--- Analysis of Android Malware Hashes ---\n\n')
            if not cursor:
                raise ValueError("Invalid database cursor provided.")

            # Count of total entries
            sql = "SELECT COUNT(*) FROM android_malware_hashes"
            cursor.execute(sql)
            total_entries = cursor.fetchone()[0]
            f.write(f"Total Entries: {total_entries}\n\n")

            # Fetch category counts
            sql = "SELECT malware_category, COUNT(*) FROM android_malware_hashes GROUP BY malware_category"
            cursor.execute(sql)
            category_counts = cursor.fetchall()

            # Iterate through categories
            for category, count in category_counts:
                f.write(f"**{category}**\n")
                f.write(f"Category Count: {count} entries\n")

                # Analyze similarities within malware categories
                similar_categories = app_utils.find_similar_categories(category, category_counts)
                f.write("Similar Categories: ")
                if similar_categories:
                    f.write(", ".join(similar_categories))
                f.write("\n\n")

            # Call to external function to write top hashes
            save_top_hashes(cursor)
            print(f"Analysis successfully written to {filename}")

    except IOError as error:
        logging.error(f"Error writing analysis to file: {error}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

def export_android_hash_data_to_file():
    filename = 'output/android_malware_data.txt'
    try:
        conn = DBConnectionManager.connect_to_database()
        cursor = conn.cursor()
        sql = "SELECT * FROM android_malware_hashes"
        cursor.execute(sql)
        rows = cursor.fetchall()
        if rows:
            headers = [i[0] for i in cursor.description]  # Extracting column headers
            max_lengths = [len(str(max([str(row[i]) for row in rows], key=len))) for i in range(len(headers))]
            headers_line = ' | '.join([headers[i].ljust(max_lengths[i]) for i in range(len(headers))])
            app_utils.write_data_to_file(filename, headers_line, max_lengths, rows)
            write_analysis_to_file(cursor)
        else:
            logging.info("No data to write")
    except Exception as error:
        logging.error(f"Error writing to file: {error}")