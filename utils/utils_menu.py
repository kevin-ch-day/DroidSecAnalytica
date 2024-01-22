from . import app_display, load_data, user_prompts

def display_menu():
    print(app_display.format_menu_title("Utility Functions"))
    print(app_display.format_menu_option(1, "API Integration Check"))
    print(app_display.format_menu_option(2, "Load Android Malware Hashes"))
    print(app_display.format_menu_option(3, "Export Malware Hash Table Data"))
    print(app_display.format_menu_option(0, "Back to Main Menu"))

def handle_api_integration():
    print("API Integration Check.")

def handle_load_android_hashes():
    try:
        load_data.load_android_malware_hash_data()
    except Exception as e:
        print(f"Error loading Android malware hashes: {e}")

def handle_export_data():
    print("Export malware hash data.")

def display_app_utils():
    while True:
        display_menu()
        choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '0'])

        if choice == '0':
            return
        
        elif choice == '1':
            handle_api_integration()
        
        elif choice == '2':
            handle_load_android_hashes()
        
        elif choice == '3':
            handle_export_data()
        
        else:
            print("Invalid option. Please try again.")