# main.py

# Python Libraries
import logging
import pandas as pd

# Custom Libraries
import static_analysis.static_analysis as static_analysis
import dynamic_analysis.dynamic_analysis as dynamic_analysis
from utils import app_utils
from database import database_manager

# Configure Logging
logging.basicConfig(
    filename='logs/main.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s')

def display_menu():
    """ Display the main menu options. """
    print(app_utils.format_menu_title("Main Menu", 24))
    print(app_utils.format_menu_option(1, "Static Analysis"))
    print(app_utils.format_menu_option(2, "Dynamic Analysis"))
    print(app_utils.format_menu_option(3, "Utilities"))
    print(app_utils.format_menu_option(4, "Database Management"))
    print(app_utils.format_menu_option(5, "Machine Learning Model"))
    print(app_utils.format_menu_option(0, "Exit"))

# Sub-menu: static analysis
def static_analysis_menu():
    print(app_utils.format_menu_title("Static Analysis Menu"))
    print(app_utils.format_menu_option(1, "Decompile APK"))
    print(app_utils.format_menu_option(2, "Create APK Record"))
    print(app_utils.format_menu_option(3, "Run Static Analysis"))
    print(app_utils.format_menu_option(4, "Metadata Analysis"))
    print(app_utils.format_menu_option(5, "Permissions Analysis"))
    print(app_utils.format_menu_option(6, "Export Static Analysis Data"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def dynamic_analysis_menu():
    print(app_utils.format_menu_title("Dynamic Analysis Menu"))
    print(app_utils.format_menu_option(1, "Run Dynamic Analysis"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def utility_functions_menu():
    print(app_utils.format_menu_title("Utility Functions Menu"))
    print(app_utils.format_menu_option(1, "API Integration Check"))
    print(app_utils.format_menu_option(3, "View Logs"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def utility_database_menu():
    print(app_utils.format_menu_title("Database Management Menu"))
    print(app_utils.format_menu_option(1, "Check database connection"))
    print(app_utils.format_menu_option(2, "Check database health"))
    print(app_utils.format_menu_option(3, "List database tables"))
    print(app_utils.format_menu_option(4, "Clear the Android hash Table"))
    print(app_utils.format_menu_option(5, "Export Android hash data"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def handle_static_analysis():
    static_analysis_menu()
    sa_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6', '0'])
    
    if sa_choice == '1':
        handle_decompile_apk()
    
    elif sa_choice == '2':
        handle_create_apk_record()
    
    elif sa_choice == '3':
        run_static_analysis()
    
    elif sa_choice == '4':
        handle_metadata_analysis()
    
    elif sa_choice == '5':
        handle_permissions_analysis()
    
    elif sa_choice == '6':
        handle_export_static_analysis_data()
    
    elif sa_choice == '0':
        return

def loadAndroidHashData():
    conn = database_manager.connect_to_database()
    cursor = conn.cursor()
    try:
        create_android_malware_table_if_not_exists(cursor)
        files_to_parse = ['input/2019-README.txt', 'input/2020-README.txt',
                         'input/2021-README.txt', 'input/2022-README.txt']

        load_data_from_files(files_to_parse)
        database_manager.close_database_connection(conn)
        print(f"Data processing completed.")

    except Exception as e:
        logging.error(f"Error during data processing: {e}")

def export_data_to_file():
    filename = 'output/android_malware_data.txt'
    try:
        with database_manager.connect_to_database() as conn, conn.cursor() as cursor:
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

def write_analysis_to_file(cursor):
    filename = 'output/analysis.txt'
    try:
        with open(filename, 'w') as f:
            f.write('--- Analysis of Android Malware Hashes ---\n\n')

            # Ensure cursor is valid
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
            write_top_hashes_to_file(cursor)
            print(f"Analysis successfully written to {filename}")

    except IOError as error:
        logging.error(f"Error writing analysis to file: {error}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

def write_top_hashes_to_file(cursor):
    filename = 'output/hash_analysis.txt'
    conn = database_manager.connect_to_database()
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
            unique_locations = database_manager.execute_sql_query(cursor, sql)
            unique_locations = unique_locations[0][0]
            analysis_file.write(f"Unique Locations: {unique_locations}\n")

            # Count of unique months
            sql = "SELECT COUNT(DISTINCT month) FROM android_malware_hashes"
            unique_months = database_manager.execute_sql_query(cursor, sql)
            unique_months = unique_months[0][0]
            analysis_file.write(f"Unique Months: {unique_months}\n")

            # Finding and fixing bad data
            sql = "SELECT COUNT(*) FROM android_malware_hashes WHERE malware_category IS NULL OR location IS NULL OR month IS NULL"
            null_data_count = database_manager.execute_sql_query(cursor, sql)
            null_data_count = null_data_count[0][0]
            analysis_file.write(f"Entries with Missing Data: {null_data_count}\n")

            sql = "SELECT COUNT(*) FROM android_malware_hashes WHERE malware_category = '' OR location = '' OR month = ''"
            empty_data_count = database_manager.execute_sql_query(cursor, sql)
            empty_data_count = empty_data_count[0][0]
            analysis_file.write(f"Entries with Empty Data: {empty_data_count}\n")

            # Count of entries per malware category
            sql = "SELECT malware_category, COUNT(*) FROM android_malware_hashes GROUP BY malware_category"
            category_counts = database_manager.execute_sql_query(cursor, sql)
            analysis_file.write("\nMalware Category Analysis:\n")
            for category, count in category_counts:
                analysis_file.write(f" '{category}': {count} entries\n")

            # Count of entries per month
            sql = "SELECT month, COUNT(*) FROM android_malware_hashes GROUP BY month"
            month_counts = database_manager.execute_sql_query(cursor, sql)
            analysis_file.write("\nMonthly Analysis:\n")
            for month, count in month_counts:
                analysis_file.write(f" {month}: {count} entries\n")

            print(f"Analysis successfully written to {filename}")

        database_manager.close_database_connection(conn)

    except IOError as error:
        logging.error(f"Error writing analysis to file: {error}")

def export_data_to_excel():
    filename = 'output/android_hash_data.xlsx'
    try:
        with database_manager.connect_to_database() as conn:
            sql = "SELECT * FROM android_malware_hashes"
            df = pd.read_sql(sql, conn)
            df.to_excel(filename, index=False)
            print(f"Data successfully exported to {filename}")
    except Exception as error:
        logging.error(f"Error exporting data to Excel: {error}")

def export_data_to_csv():
    filename = 'output/android_hash_data.csv'
    try:
        with database_manager.connect_to_database() as conn:
            query = "SELECT * FROM android_malware_hashes"
            df = pd.read_sql(query, conn)
            df.to_csv(filename, index=False)
            print(f"Data successfully exported to {filename}")
    except Exception as error:
        logging.error(f"Error exporting data to CSV: {error}")

def viewAndroidHashTableSummary():
    conn = database_manager.connect_to_database()
    cursor = conn.cursor()
    sql = "SELECT COUNT(*) FROM android_malware_hashes"
    result = database_manager.execute_sql_query(cursor, sql)
    print(f"Total Records in Database: {result[0][0]}")
    database_manager.close_database_connection(conn)

def create_android_malware_table_if_not_exists(cursor):
    result = database_manager.check_for_table(cursor, 'android_malware_hashes')
    if not result:
        sql_create_table = '''
            CREATE TABLE android_malware_hashes (
                id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                malware_category VARCHAR(255) DEFAULT NULL,
                md5 VARCHAR(250) DEFAULT NULL,
                sha1 VARCHAR(250) DEFAULT NULL,
                sha256 VARCHAR(250) DEFAULT NULL,
                location VARCHAR(100) DEFAULT NULL,
                month VARCHAR(100) DEFAULT NULL)
        '''
        cursor.execute(sql_create_table)

def load_data_from_files(files_to_parse):
    try:
        with database_manager.connect_to_database() as conn, conn.cursor() as cursor:
            for file in files_to_parse:
                parsed_data = app_utils.parse_file(file)
                if not parsed_data:
                    print(f"No valid data parsed from {file}.")
                    continue

                sql_insert_data = "INSERT INTO android_malware_hashes (malware_category, md5, sha1, sha256, location, month) VALUES (%s, %s, %s, %s, %s, %s)"
                cursor.executemany(sql_insert_data, parsed_data)
                conn.commit()
                print(f"Data from {file} inserted successfully.")
                print(f"Total records inserted: {len(parsed_data)}\n")
    except Exception as e:
        logging.error(f"Error in load_data_from_files: {e}")
        print(f"Error occurred while processing file {file}.")

# Handling creation of APK record
def handle_create_apk_record():
    print("Creating APK record...")

# Handling metadata analysis
def handle_metadata_analysis():
    print("Performing metadata analysis...")

# Handling permissions analysis
def handle_permissions_analysis():
    print("Performing permissions analysis...")

# Handling export of static analysis data
def handle_export_static_analysis_data():
    print("Exporting static analysis data...")

def run_static_analysis():
    apk_path = android_apk_selection()
    static_analysis.run_static_analysis(apk_path)

def handle_decompile_apk():
    apk_path = android_apk_selection()
    static_analysis.decompile_apk(apk_path)

def android_apk_selection():
    apk_files = app_utils.display_apk_files()
    if not apk_files: return
    apk_choice = app_utils.get_user_choice("Select an APK option: ", [str(i) for i in range(1, len(apk_files)+1)])
    return apk_files[int(apk_choice) - 1]

def handle_dynamic_analysis():
    dynamic_analysis_menu()
    da_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '0'])
    if da_choice == '1':
        apk_path = input("Enter the path to the APK: ").strip()
        dynamic_analysis.run_dynamic_analysis(apk_path)

def handle_utilities():
    utility_functions_menu()
    utility_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '0'])

    if utility_choice == '1':
        print("API Integration Check.")

    elif utility_choice == '0':
        app_utils.handle_view_logs()

def handle_database_management():
    utility_database_menu()
    utility_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '0'])
    if utility_choice == '1':
        database_manager.test_database_connection()
    
    elif utility_choice == '2':
        database_manager.database_health_check()
    
    elif utility_choice == '3':
        conn = database_manager.connect_to_database()
        database_manager.list_tables(conn)

    elif utility_choice == '4':
        database_manager.truncate_table('android_malware_hashes')
    
    elif utility_choice == '5':
        export_data_to_file()
        export_data_to_excel()
        export_data_to_csv()

def handle_machine_learning():
    # Placeholder for machine learning models menu
    print("Machine Learning Models - Feature Coming Soon")

def main_menu():
    while True:
        display_menu()

        choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '0'])

        if choice == '1':
            handle_static_analysis()
        
        elif choice == '2':
            handle_dynamic_analysis()
        
        elif choice == '3':
            handle_utilities()

        elif choice == '4':
            handle_database_management()

        elif choice == '5':
            handle_machine_learning()

        elif choice == '0':
            if input("Are you sure you want to exit? (y/n): ").lower() == 'y':
                print("Exiting. Goodbye!\n")
                break

        input("\nEnter any key to return to Main Menu.")

def main():
    app_utils.display_app_name()
    main_menu()

if __name__ == "__main__":
    main()