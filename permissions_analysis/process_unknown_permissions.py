# process_unknown_permissions.py

from . import data_process, missing_vendor_analysis

def main():
    while True:
        user_choice = show_main_menu()
        if user_choice == 0:
            print("Exiting program.")
            break
        elif user_choice == 1:
            data_process.check_unknown_permission_for_vendors()
        elif user_choice == 2:
            data_process.remove_duplicate_permissions()
        elif user_choice == 3:
            missing_vendor_analysis.check_for_missing_vendors()
        elif user_choice == 4:
            data_process.fetch_and_save_unknown_permissions()
        elif user_choice == 5:
            data_process.fetch_and_save_manufacturer_permissions()
        elif user_choice == 6:
            data_process.save_vendor_manufacturer_permission_prefixes()
        elif user_choice == 7:
            data_process.fix_manufacturer_permissions()
        else:
            print("Invalid option, please try again.")

def show_main_menu():
    print("\n=== Main Menu ===")
    print("1. Check Unknown Permissions for Vendors")
    print("2. Remove Duplicate Permissions")
    print("3. Check for Missing Vendors")
    print("4. Fetch and Save Unknown Permissions to Excel")
    print("5. Fetch and Save Manufacturer Permissions to Excel")
    print("6. Save Vendor Manufacturer Permission Prefixes")
    print("7. Fix manufacturer permissions")
    print("0. Exit")
    print("=================")
    
    try:
        choice = int(input("\nEnter your choice: "))
    except ValueError:
        print("Please enter a valid number.")
        return -1  # Return -1 to indicate an invalid choice

    return choice

if __name__ == "__main__":
    main()
