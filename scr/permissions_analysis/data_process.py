import pandas as pd
import os

from database import db_permission_2
from  utils import display_perm_utils

def remove_duplicate_permissions():
    display_perm_utils.print_header("Removing Duplicate Permissions")
    unknown_permissions = db_permission_2.fetch_unknown_permissions()
    manufacturer_permissions = db_permission_2.fetch_manufacturer_permissions()
    
    # Convert the list of dictionaries to sets for faster lookup
    manufacturer_perm_set = {perm['constant_value'] for perm in manufacturer_permissions}

    removed_count = 0
    for perm in unknown_permissions:
        # Check if the permission's constant_value exists in the manufacturer permissions
        if perm['constant_value'] in manufacturer_perm_set:
            # If it exists, delete it from the unknown permissions table
            if db_permission_2.remove_permission_from_unknown_table(perm['permission_id']):
                removed_count += 1
                print(f"Removed duplicate permission: {perm['constant_value']}")

    print(f"Total duplicate permissions removed: {removed_count}")

def save_vendor_manufacturer_permission_prefixes():
    display_perm_utils.print_header("Vendor Manufacturer Permission Prefixes")
    data = db_permission_2.fetch_vendor_manufacturer_permission_prefixes()
    if data:
        save_permissions_to_excel(data, "unknown_permissions.xlsx")
    else:
        display_perm_utils.display_error("No unknown permissions found.")

def fetch_unknown_permission_prefixes():
    display_perm_utils.print_header("Unknown Permission Prefixes")
    data = db_permission_2.fetch_all_unknown_permission_prefixes()
    if data:
        df = pd.DataFrame(data)
        display_perm_utils.display_results(df, "Unknown Permission Prefixes")
        display_perm_utils.visualize_data(df, chart_type='pie', title="Unknown Permissions Distribution")
    else:
        display_perm_utils.display_error("No data available.")

def check_unknown_permission_for_vendors():
    print("\nChecking unknown permissions table for vendors...")
    unknown_permissions = db_permission_2.fetch_unknown_permissions()
    vendor_data = db_permission_2.fetch_vendor_data()
    process_permissions(unknown_permissions, vendor_data)

def categorize_permissions(unknown_permissions, manufacturer_prefixes):
    skip_prefixes = ['android.permission', 'android.settings', 'com.android']
    permissions_by_vendor = {}
    unrecognized_permissions = {}
    for perm in unknown_permissions:
        if not any(perm['constant_value'].startswith(skip) for skip in skip_prefixes):
            prefix = extract_permission_prefix(perm['constant_value'])
            vendor = manufacturer_prefixes.get(prefix)
            if vendor:
                permissions_by_vendor.setdefault(vendor['vendor'], []).append(perm['constant_value'])
            else:
                unrecognized_permissions.setdefault(prefix, []).append(perm['constant_value'])
    return permissions_by_vendor, unrecognized_permissions

def process_permissions(unknown_permissions, vendor_data):
    manufacturer_prefixes = {vendor['prefix']: vendor for vendor in vendor_data}
    permissions_by_vendor, unrecognized_permissions = categorize_permissions(unknown_permissions, manufacturer_prefixes)
    if not permissions_by_vendor:
        print("No duplicate permissions in either permission table.")
        return
    
    display_perm_utils.display_vendor_permissions(permissions_by_vendor)
    display_perm_utils.display_unrecognized_permissions(unrecognized_permissions)
    display_perm_utils.confirm_and_migrate_permissions(permissions_by_vendor, unknown_permissions, migrate_permissions_to_manufacturer_table)

def migrate_permissions_to_manufacturer_table(permissions_by_vendor, unknown_permissions):
    total_migrated, errors = perform_migration(permissions_by_vendor, unknown_permissions)
    display_perm_utils.print_migration_summary(total_migrated, errors)

def perform_migration(permissions_by_vendor, unknown_permissions):
    migrated_count = 0
    errors = []
    for vendor, perms in permissions_by_vendor.items():
        for perm in perms:
            result, error = migrate_permission(perm, unknown_permissions)
            if result: migrated_count += 1
            if error: errors.append(error)
    return migrated_count, errors

def migrate_permission(permission, unknown_permissions):
    # Find the permission record in the unknown permissions list
    record = next((p for p in unknown_permissions if p['constant_value'] == permission), None)

    # Check if the permission already exists in the android_manufacturer_permissions table
    if not db_permission_2.check_constant_value_exists(record['constant_value']):
        
        # If the record is found
        if record:
            # Attempt to insert the permission into the manufacturer table and remove it from the unknown table
            success_insert = db_permission_2.insert_permission_into_manufacturer_table(record)
            success_remove = db_permission_2.remove_permission_from_unknown_table(record['permission_id'])
            
            # If both operations are successful
            if success_insert and success_remove:
                return True, None
        # If migration fails
        return False, f"Migration failed for permission: {permission}"


def extract_permission_prefix(permission):
    return '.'.join(permission.split('.')[:2])

def matches_manufacturer_prefix(permission, manufacturer_prefixes):
    return any(permission.startswith(prefix) for prefix in manufacturer_prefixes.keys())

def fetch_and_save_unknown_permissions():
    """
    Fetches unknown permissions and saves them to an Excel sheet.
    """
    display_perm_utils.print_header("Unknown Permissions")
    data = db_permission_2.fetch_unknown_permissions()
    if data:
        save_permissions_to_excel(data, "unknown_permissions.xlsx")
    else:
        display_perm_utils.display_error("No unknown permissions found.")

def fetch_and_save_manufacturer_permissions():
    """
    Fetches manufacturer permissions and saves them to an Excel sheet.
    """
    display_perm_utils.print_header("Manufacturer Permissions")
    data = db_permission_2.fetch_manufacturer_permissions()
    if data:
        save_permissions_to_excel(data, "manufacturer_permissions.xlsx")
    else:
        display_perm_utils.display_error("No manufacturer permissions found.")

def fix_manufacturer_permissions():
    print("Starting to process duplicate manufacturer permissions entries...")
    duplicates = db_permission_2.find_duplicate_constant_values()
    total_deleted = 0
    if not duplicates:
        print("No duplicates found.")
        return

    for duplicate in duplicates:
        constant_value, count = duplicate['constant_value'], duplicate['cnt']
        print(f"Processing {constant_value} with {count - 1} duplicates to delete...")
        id_to_keep = db_permission_2.get_id_to_keep_for_duplicate(constant_value)
        if id_to_keep:
            deleted_rows = db_permission_2.delete_duplicate_rows(constant_value, id_to_keep)
            total_deleted += deleted_rows
            print(f"Deleted {deleted_rows} duplicate rows for constant_value '{constant_value}'.")
    
    print(f"Process completed. Total duplicate rows deleted: {total_deleted}.")

def save_permissions_to_excel(data, filename):
    """
    Saves the fetched permissions data to an Excel file.
    """
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    file_path = os.path.join(output_dir, filename)
    
    df = pd.DataFrame(data)
    df.to_excel(file_path, index=False)
    print(f"Data saved to {file_path}")
