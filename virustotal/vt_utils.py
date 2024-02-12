import requests
import socket
import subprocess
import platform
import json
import os
from datetime import datetime

from utils import user_prompts, logging_utils
from . import vt_requests

def check_ping():
    ip = "8.8.8.8"
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ["ping", param, "1", ip]

    try:
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if response.returncode == 0:
            print(f"Successfully pinged {ip}.")
            return True
        else:
            print(f"Failed to ping {ip}. Response: {response.stderr}")
            return False
    except Exception as e:
        print(f"An error occurred while trying to ping: {e}")
        return False

def check_virustotal_access():
    url = 'https://www.virustotal.com'
    try:
        host = socket.gethostbyname('www.virustotal.com')
        print("DNS resolution successful.")
    except socket.gaierror:
        print("Failed to resolve VirusTotal's domain. Check your DNS settings.")
        return False

    try:
        socket.create_connection((host, 80), 2)
        print("Network connection to VirusTotal established.")
    except OSError:
        print("Network connection to VirusTotal failed. Check your network.")
        return False

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print("Successfully connected to VirusTotal.")
            return True
        else:
            print(f"Connected to VirusTotal, but received a non-success status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"HTTP request to VirusTotal failed: {e}")
        return False

def set_data_if_key_exists(key, setter_function, data):
    if key in data:
        setter_function(data[key])

def add_items_to_list_if_key_exists(key, add_function, data):
    if key in data:
        for item in data[key]:
            add_function(item)

def save_json_response(response, filename, overwrite=True):
    if not isinstance(response, dict):
        print("Error: Response must be a dictionary.")
        return

    try:
        if os.path.exists(filename) and not overwrite:
            print(f"File '{filename}' already exists. Use 'overwrite=True' to overwrite.")
            return

        with open(filename, 'w') as file:
            json.dump(response, file, indent=4)
        print(f"Response saved to '{filename}'")
    except Exception as e:
        print(f"Error saving response to file: {e}")

def submit_apk():
    apk_file_path = user_prompts.user_enter_apk_path()
    if os.path.isfile(apk_file_path):
        try:
            return vt_requests.query_apk(apk_file_path)
        except Exception as e:
            print(f"Error submitting the APK: {e}")
    else:
        print("Invalid APK file path.")

def submit_hash():
    hash_value = user_prompts.user_enter_hash_ioc()
    try:
        return vt_requests.query_hash(hash_value)
    except Exception as e:
        print(f"Error submitting the hash: {e}")

def format_timestamp(timestamp):
    try:
        # Check if the timestamp is in milliseconds and convert to seconds if necessary
        if isinstance(timestamp, (int, float)) and timestamp > 1e10:
            timestamp /= 1000

        return datetime.fromtimestamp(timestamp).strftime('%I:%M:%S %p %m-%d-%Y') if timestamp else 'N/A'
    except (TypeError, ValueError, OverflowError):
        return 'Invalid Timestamp'

def format_file_size(size):
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def display_main_activity(androguard_data):
    print("\n-- Main Analysis --")
    print(f"Main Activity: {androguard_data.get_main_activity()}")
    print(f"Package: {androguard_data.get_package()}")
    print(f"Target SDK Version: {androguard_data.get_target_sdk_version()}\n")

def display_manifest_components(androguard_data):
    try:
        sections = ['Activities', 'Receivers', 'Providers', 'Services', 'Libraries']
        is_data_present = False
        for section in sections:
            items = getattr(androguard_data, f'get_{section.lower()}')()
            if items:
                is_data_present = True
                print(f"{section} ({len(items)} items):")
                for item in items:
                    print(item)
                print()

        if not is_data_present:
            print("No data available in any section.")

    except AttributeError as e:
        print(f"Attribute Error: {str(e)} - Check if the method exists in androguard_data.")
    
    except Exception as e:
        logging_utils.log_error(f"Error processing sections: {str(e)}")

def display_certificate_details(androguard_data):
    try:
        print("\n-- Certificate Details --")
        if not androguard_data or not hasattr(androguard_data, 'get_certificate_data'):
            logging_utils.log_error("Invalid or no androguard data provided for certificate details.")
            return

        certificate_data = androguard_data.get_certificate_data()
        if not certificate_data:
            print("No certificate data available.")
            return

        for section, section_data in certificate_data.items():
            if isinstance(section_data, dict):
                print(f"{section}")
                for key, value in section_data.items():
                    print(f"  {key}: {value}")
            else:
                print(f"{section}:  {section_data}")

    except Exception as e:
        logging_utils.log_error(f"Error processing certificate details: {str(e)}")

def display_permissions(androguard_data):
    try:
        permissions = androguard_data.get_permissions()
        print("\n-- Permissions --")
        if not permissions:
            logging_utils.log_warning("No permissions data provided to display.")
            return

        # Sort permissions by name
        sorted_permissions = sorted(permissions, key=lambda perm: perm.name)

        # Determine dynamic column widths based on maximum data length
        max_name_width = max(len("Permission Name"), max(len(perm.name) for perm in sorted_permissions)) + 2
        max_type_width = max(len("Permission Type"), max(len(perm.permission_type) for perm in sorted_permissions)) + 2
        max_desc_width = max(len("Description"), max(len(perm.short_desc) for perm in sorted_permissions)) + 2

        # Create header with column labels
        header = f"Permission Name".ljust(max_name_width) + f"Permission Type".ljust(max_type_width) + f"Description".ljust(max_desc_width)
        print(header)
        print("-" * len(header))  # Print a separator line

        for perm in sorted_permissions:
            # Format and print permission details in a tabular format
            permission_name = perm.name[:max_name_width - 1].ljust(max_name_width)
            permission_type = perm.permission_type[:max_type_width - 1].ljust(max_type_width)
            permission_desc = perm.short_desc[:max_desc_width - 1].ljust(max_desc_width)

            # Add line separator after each permission for better readability
            print(f"{permission_name}{permission_type}{permission_desc}")

    except Exception as e:
        logging_utils.log_error(f"Error processing permissions: {str(e)}")

def display_intent_filters(androguard_data):
    print("\nIntent Filters:")

    if not androguard_data or not hasattr(androguard_data, 'get_all_intent_filters'):
        print("Invalid or no data provided.")
        return

    intent_filters = androguard_data.get_all_intent_filters()
    if not intent_filters:
        print("No intent filters to display.")
        return

    for entity_type, entities in intent_filters.items():
        print(f"\n--- {entity_type} ({len(entities)} Entities) ---")
        if not entities:
            print("  No entities found.")
            continue

        for entity, filters in entities.items():
            actions = ', '.join(filters.get('action', [])) or "None"
            categories = ', '.join(filters.get('category', [])) or "None"
            
            print(f"\n  {entity}:")
            print(f"    Actions: {actions}")
            print(f"    Categories: {categories}")

    intent_filters_summary(intent_filters)

def intent_filters_summary(intent_filters):
    total_entities = sum(len(entities) for entities in intent_filters.values())
    total_actions = sum(len(filters.get('action', [])) for entities in intent_filters.values() for filters in entities.values())
    total_categories = sum(len(filters.get('category', [])) for entities in intent_filters.values() for filters in entities.values())

    print("\nSummary:")
    print(f"Total Entities: {total_entities}")
    print(f"Total Actions: {total_actions}")
    print(f"Total Categories: {total_categories}")

    for entity_type, entities in intent_filters.items():
        entity_count = len(entities)
        action_count = sum(len(filters.get('action', [])) for filters in entities.values())
        category_count = sum(len(filters.get('category', [])) for filters in entities.values())

        if total_entities > 0:
            entity_percentage = entity_count / total_entities * 100
        else:
            entity_percentage = 0

        if total_actions > 0:
            action_percentage = action_count / total_actions * 100
        else:
            action_percentage = 0

        if total_categories > 0:
            category_percentage = category_count / total_categories * 100
        else:
            category_percentage = 0

        print(f"\n{entity_type} Breakdown:")
        print(f"  Entities: {entity_count} ({entity_percentage:.2f}%)")
        print(f"  Actions: {action_count} ({action_percentage:.2f}%)")
        print(f"  Categories: {category_count} ({category_percentage:.2f}%)")

def view_summary_statistics(report_data):
    if "Analysis Result" in report_data:
        summary_statistics = report_data["Analysis Result"].get("summary_statistics", {})
        print("\nSummary Statistics:")
        for key, value in summary_statistics.items():
            print(f"{key}:".ljust(25), value)
    else:
        print("Summary statistics not available.")

def view_detection_breakdown(report_data):
    if "Analysis Result" in report_data:
        detection_breakdown = report_data["Analysis Result"].get("engine_detection", [])
        if detection_breakdown:
            print("\nDetection Breakdown:")
            for item in detection_breakdown:
                engine_name, detection_label = item[0], item[1]
                print(f"{engine_name.ljust(30)}: {detection_label}")
        else:
            print("Detection breakdown not available.")
    else:
        print("Detection breakdown not available.")