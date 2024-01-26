import re
from utils import logging_utils
from . import vt_utils, PermissionADT

def parse_basic_data(androguard_data, data):
    if not androguard_data:
        print("Error: androguard_data is None or invalid.")
        return

    try:
        # Setting basic data using setter functions
        basic_data_settings = [
            ('main_activity', androguard_data.set_main_activity),
            ('Package', androguard_data.set_package),
            ('TargetSdkVersion', androguard_data.set_target_sdk_version)
        ]

        for key, setter_function in basic_data_settings:
            if key in data and data[key] is not None:
                print(f"Setting {key} to {data[key]}")
                setter_function(data[key])
            else:
                print(f"Key '{key}' not found or is None in data.")

        # Adding items to Androguard data
        add_functions = [
            ('Activities', androguard_data.add_activity),
            ('Receivers', androguard_data.add_receiver),
            ('Providers', androguard_data.add_provider),
            ('Services', androguard_data.add_service),
            ('Libraries', androguard_data.add_library)
        ]

        for key, add_function in add_functions:
            if key in data:
                if isinstance(data[key], list):
                    for item in data[key]:
                        if item:
                            add_function(item)
                        else:
                            print(f"Found empty item in {key}. Skipping.")
                else:
                    print(f"Data for {key} is not in list format.")
            else:
                print(f"Key '{key}' not found in data.")

    except Exception as e:
        print(f"Error parsing Androguard data: {str(e)}")


def parse_permissions(androguard_data, data):
    if 'permission_details' in data:
        permission_data = parse_permission_details(data['permission_details'])
        for permission in permission_data:
            permission_obj = PermissionADT.PermissionADT(*permission)
            
            # Remove newline characters and replace multiple spaces with a single space
            cleaned_short_desc = re.sub(' +', ' ', ' '.join(permission_obj.short_desc.splitlines()))
            permission_obj.short_desc = cleaned_short_desc.strip()
            androguard_data.add_permission(permission_obj)

def parse_intent_filters(androguard_data, data):
    if 'intent_filters' not in data:
        print("No 'intent_filters' key found in the data.")
        return

    for filter_type, components in data['intent_filters'].items():
        if filter_type not in androguard_data.intent_filters.valid_entity_types:
            print(f"Invalid filter type: {filter_type}")
            continue

        print(f"\n{filter_type}")  # Print the filter type heading
        for component, filters in components.items():
            # Extract actions and categories
            action = filters.get('action', []) if isinstance(filters.get('action'), list) else []
            category = filters.get('category', []) if isinstance(filters.get('category'), list) else []

            # Store the results in androguard_data
            androguard_data.add_intent_filter(filter_type, component, action, category)

            # Print the intent filters
            #print_intent_filters(component, action, category)

def parse_certificate_data(androguard_data, data):
    if 'certificate' in data:
        cert_data = parse_certificate(data['certificate'])
        androguard_data.set_certificate_data(cert_data)

def parse_permission_details(permission_details):
    parsed_data = []
    for permission, details in permission_details.items():
        short_description = details.get('short_description', 'N/A')
        full_description = details.get('full_description', 'N/A')
        permission_type = details.get('permission_type', 'N/A')
        parsed_data.append([permission, short_description.capitalize(), full_description, permission_type.title()])
    return parsed_data

def parse_certificate(certificate_data):
    parsed_info = {}
    subject_info = certificate_data.get('Subject', {})
    parsed_info['Subject'] = {
        'DN': subject_info.get('DN', 'N/A'),
        'C': subject_info.get('C', 'N/A'),
        'CN': subject_info.get('CN', 'N/A')
    }
    
    issuer_info = certificate_data.get('Issuer', {})
    parsed_info['Issuer'] = {
        'DN': issuer_info.get('DN', 'N/A'),
        'C': issuer_info.get('C', 'N/A'),
        'CN': issuer_info.get('CN', 'N/A')
    }
    
    parsed_info['validto'] = certificate_data.get('validto', 'N/A')
    parsed_info['serialnumber'] = certificate_data.get('serialnumber', 'N/A')
    parsed_info['thumbprint'] = certificate_data.get('thumbprint', 'N/A')
    parsed_info['validfrom'] = certificate_data.get('validfrom', 'N/A')
    
    return parsed_info