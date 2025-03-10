# user_prompts.py

import os

# Get and validate user menu choice from a list of valid options
def user_menu_choice(prompt, valid_choices):
    while True:
        try:
            choice = input(prompt).strip()
            
            # Check if the user's choice is in the list of valid choices
            if choice in valid_choices:
                return choice
            
            print("Invalid choice. Please select a valid option.")
        
        except KeyboardInterrupt:
            # Handle unexpected exit gracefully (e.g., Ctrl+C)
            print("\nOperation cancelled by user.")
            exit(0)

# Prompt user to enter a valid file path for an APK and validate it
def user_enter_apk_path():
    cnt = 0
    while True:
        cnt += 1
        user_data = input("\nEnter the path to the APK file: ").strip()

        # Validate that the path is not empty, exists, and is a file
        if user_data and os.path.exists(user_data) and os.path.isfile(user_data):
            return user_data
        else:
            print("Invalid path or file. Please enter a valid path.")

        if cnt == 3:
            print("Returning to menu")
            return False

# Prompt user to enter a hash Indicator of Compromise (IOC) and validate it
def user_enter_hash_ioc():
    cnt = 0
    while True:
        cnt += 1
        user_data = input("\nEnter the hash IOC: ").strip()

        # Validate if the input is a non-empty hexadecimal string of common hash lengths
        if user_data:
            if all(c in '0123456789abcdefABCDEF' for c in user_data):
                if len(user_data) in [32, 40, 64]:
                    return user_data
                else:
                    print("Invalid hash length. Please enter a valid MD5, SHA1, or SHA256 hash.")
            else:
                print("Invalid hash. Hashes should contain hexadecimal characters only.")
        else:
            print("Please enter a valid hash.")

        if cnt == 3:
            print("Returning to menu")
            return False

# Prompt user for a yes/no confirmation
def user_for_confirmation(prompt):
    while True:
        user_input = input(prompt + " (yes/no): ").strip().lower()
        if user_input in ["yes", "y"]:
            return True
        elif user_input in ["no", "n"]:
            return False
        else:
            print("Please enter 'yes' or 'no'.")

# Pauses the program execution and waits for the user to press any key to continue.
def pause_until_keypress():
    try:
        input("\nPress any key to continue...")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        exit(0)

# Prompt user for input with custom validation
def user_for_input_with_validation(prompt, validation_func, error_msg):
    while True:
        user_input = input(prompt).strip()
        if validation_func(user_input):
            return user_input
        else:
            print(error_msg)