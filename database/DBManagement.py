import database.DBUtils as DBUtils
from utils import app_utils, export_data

def database_management_menu():
    print(app_utils.format_menu_title("Database Management Menu"))
    print(app_utils.format_menu_option(1, "Check database connection"))
    print(app_utils.format_menu_option(2, "Check database health"))
    print(app_utils.format_menu_option(3, "Display database table info"))
    print(app_utils.format_menu_option(4, "Clear the Android hash Table"))
    print(app_utils.format_menu_option(5, "Export Android hash data"))
    print(app_utils.format_menu_option(0, "Back to Main Menu"))

def handle_database_management():
    while True:
        database_management_menu()
        utility_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5','0'])
        if utility_choice == '0':
            return
        
        elif utility_choice == '1':
            DBUtils.test_database_connection()
        
        elif utility_choice == '2':
            DBUtils.database_health_check()
        
        elif utility_choice == '3':
            DBUtils.display_tables_info()
        
        elif utility_choice == '4':
            DBUtils.empty_table('android_malware_hashes')
        
        elif utility_choice == '5':
            export_data.android_hash_data_to_file()
            export_data.android_hash_data_to_excel()
            export_data.android_hash_data_to_csv()