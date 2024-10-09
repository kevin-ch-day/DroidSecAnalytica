from datetime import datetime
from . import db_vt_api_keys
from utils import app_display, user_prompts

# Displays and handles the menu for managing VirusTotal API keys
def vt_api_key_menu():
    while True:
        print(app_display.format_menu_title("VirusTotal API Key Management"))
        print(app_display.format_menu_option(1, "View All Keys"))
        print(app_display.format_menu_option(2, "Add New Key"))
        print(app_display.format_menu_option(3, "Delete a Key"))
        print(app_display.format_menu_option(0, "Main Menu"))

        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '0'])

        if menu_choice == '0':
            break

        elif menu_choice == '1':
            view_api_keys()

        elif menu_choice == '2':
            add_api_key()

        elif menu_choice == '3':
            delete_api_key()

        input("\nPress any key to continue.")

# Displays all the VirusTotal API keys in the database
def view_api_keys():
    api_keys = db_vt_api_keys.view_all_api_keys()

    if api_keys:
        # Determine the length of the longest API key for proper formatting
        longest_api_key_length = max(len(key[1]) for key in api_keys)

        print("\n" + "=" * (longest_api_key_length + 80))
        print("          *** VIRUSTOTAL API KEYS ***          ")
        print("=" * (longest_api_key_length + 80))

        # Adjusted header for the longer API key length with more space before 'Type'
        header = f"{'ID':<5} {'API Key':<{longest_api_key_length + 5}} {'Type':<12} {'Requests':<12} {'Max':<8} {'Last Used (Time)'}"
        print(header)
        print("-" * len(header))

        # Loop through API keys and display them in the correct format
        for key in api_keys:
            id_display = f"{key[0]:<5}"
            api_key_display = f"{key[1]:<{longest_api_key_length + 5}}"  # Full API key with extra space
            type_display = f"{key[2]:<12}"
            current_requests_display = f"{key[4]:<12}"
            max_requests_display = f"{key[3]:<8}"
            last_used_display = format_last_used(key[5]) if key[5] else "Never Used"

            print(f"{id_display}{api_key_display}{type_display}{current_requests_display}{max_requests_display}{last_used_display}")

        # Display current date and time at the end
        print("\n" + "=" * (longest_api_key_length + 80))
        print(f"Current Date and Time: {datetime.now().strftime('%I:%M %p %B %d, %Y')}")
    
    else:
        print("[INFO] No API keys available.")

# Helper function to format the last used timestamp
def format_last_used(last_used):
    if last_used:
        return datetime.strptime(str(last_used), '%Y-%m-%d %H:%M:%S').strftime('%I:%M %p %B %d, %Y')
    return "Never Used"

# Prompts user to input and add a new VirusTotal API key to the database
def add_api_key():
    api_key = input("Enter the new VirusTotal API Key: ").strip()
    api_type = user_prompts.user_menu_choice("Select API Type (free or premium): ", ['free', 'premium'])

    if db_vt_api_keys.insert_vt_api_key(api_key, api_type):
        print(f"The key was successfully added.")
    else:
        print("Failed to add the new API key.")

def delete_api_key():
    # Display custom view of API keys (only ID and API Key)
    view_api_keys_simple()

    try:
        api_key_id = int(input("Enter the ID to delete: "))
        confirm = input(f"Are you sure you want to delete ID {api_key_id}? (y/n): ")

        if confirm.lower() == 'y':
            if db_vt_api_keys.delete_api_key(api_key_id):
                print(f"API key with ID {api_key_id} has been deleted.")
            else:
                print(f"Failed to delete API key with ID {api_key_id}.")
        else:
            print("Deletion cancelled.")

    except ValueError:
        print("Invalid ID entered. Please enter a numeric value.")


def view_api_keys_simple():
    api_keys = db_vt_api_keys.view_all_api_keys()

    if not api_keys:
        print("\nNo API keys available.")
        return

    print("\n===========================================")
    print("          *** VIRUSTOTAL API KEYS ***")
    print("===========================================")
    print(f"{'ID':<5} {'API Key':<55}")
    print("-------------------------------------------")

    for index in api_keys:
        print(f"{index[0]:<5} {index[1]:<55}")

    print("\n")

