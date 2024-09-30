# check_for_missing_vendors.py

from db_operations import db_permission_2
from utils import display_perm_utils

def get_permissions_by_vendor(manufacturer_permissions):
    permissions_by_vendor = {}
    for perm in manufacturer_permissions:
        vendor = perm.get('vendor')
        if vendor:
            permissions_by_vendor.setdefault(vendor, []).append(perm['constant_value'])
    return permissions_by_vendor

def get_vendor_details_set(vendor_details):
    vendor_details_set = {}
    for vendor in vendor_details:
        vendor_name = vendor['vendor'].title()  # Ensure consistent capitalization
        vendor_prefix = vendor['prefix']
        
        vendor_details_set[vendor_name] = vendor_prefix

    return vendor_details_set

def analyze_missing_vendors(permissions_by_vendor, detail_vendors):
    missing_vendors = sorted(set(permissions_by_vendor) - set(detail_vendors.keys()))
    return missing_vendors

def print_missing_vendors_info(missing_vendors, permissions_by_vendor, detail_vendors):
    if missing_vendors:
        print("Missing vendors from vendor_details table, with associated permission counts:")
        for vendor in missing_vendors:
            count = len(permissions_by_vendor[vendor])
            prefix = detail_vendors.get(vendor, "N/A")
            print(f" -- {vendor} [{prefix}]: {count} permissions")
    else:
        print("No missing vendors found.")

def print_present_vendors_info(permissions_by_vendor, detail_vendors):
    present_vendors = set(detail_vendors.keys()).intersection(set(permissions_by_vendor))
    if present_vendors:
        print("\nAnalysis of present vendors and their permission counts:")
        for vendor in sorted(present_vendors):
            count = len(permissions_by_vendor[vendor])
            prefix = detail_vendors[vendor]
            print(f" -- {vendor} [{prefix}]: {count} permissions")
    else:
        print("\nNo present vendors found for analysis.")

def check_for_missing_vendors():
    """
    Enhanced analysis of missing vendors in android_manufacturer_permissions against vendor_details.
    Includes vendor prefixes in the analysis and displays.
    """
    display_perm_utils.print_header("Checking for Missing Vendors")

    # Fetch data from the database
    manufacturer_permissions = db_permission_2.fetch_manufacturer_permissions()
    vendor_details = db_permission_2.fetch_vendor_data()

    # Analyze permissions and vendors
    permissions_by_vendor = get_permissions_by_vendor(manufacturer_permissions)
    detail_vendors = get_vendor_details_set(vendor_details)
    missing_vendors = analyze_missing_vendors(permissions_by_vendor, detail_vendors)

    print_missing_vendors_info(missing_vendors, permissions_by_vendor, detail_vendors)
    print_present_vendors_info(permissions_by_vendor, detail_vendors)

    # Encourage user to update missing vendors
    if missing_vendors:
        print("\nConsider adding the missing vendors to the vendor_details table to ensure comprehensive analysis.")

