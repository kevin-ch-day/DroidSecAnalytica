import re
from . import AndroguardADT, AndroPermissionADT
from utils import logging_utils

def androguard_data(response):
    try:
        attributes = extract_attributes_from_response(response)
        
        androguard_data = populate_androguard_data(attributes)
        
        return androguard_data

    except Exception as e:
        logging_utils.log_error(f"Error in generate_androguard_data: {e}")
        return None

def extract_attributes_from_response(response):
    data = response.get('data', {})
    if not data:
        raise ValueError("No 'data' key in response.")
    return data.get('attributes', {})

def populate_androguard_data(attributes):
    json_data = attributes.get('androguard', None)
    if not json_data:
        return None


    androguard = AndroguardADT.AndroguardADT()
    populate_manifest_data(androguard, json_data)
    populate_permissions(androguard, json_data)
    populate_certificate_data(androguard, json_data)
    populate_intent_filters(androguard, json_data)
    return androguard

def populate_manifest_data(androguard_data, data):
    if not androguard_data:
        print("Error: androguard_data is None or invalid.")
        return

    try:
        # Setting basic manifest data
        basic_data_settings = [
            ('main_activity', androguard_data.set_main_activity),
            ('Package', androguard_data.set_package),
            ('TargetSdkVersion', androguard_data.set_target_sdk_version)
        ]

        for key, setter_function in basic_data_settings:
            if key in data and data[key] is not None:
                setter_function(data[key])

        # Adding manifest components like Activities, Receivers, etc.
        add_functions = [
            ('Activities', androguard_data.add_activity),
            ('Receivers', androguard_data.add_receiver),
            ('Providers', androguard_data.add_provider),
            ('Services', androguard_data.add_service),
            ('Libraries', androguard_data.add_library)
        ]

        for key, add_function in add_functions:
            for item in data.get(key, []):
                if item:
                    add_function(item)

    except Exception as e:
        print(f"Error parsing Androguard data: {str(e)}")

def populate_permissions(androguard_data, data):
    if 'permission_details' in data:
        permission_details = data['permission_details']

        for permission, details in permission_details.items():
            # Extract permission details
            short_description = details.get('short_description', 'N/A')
            
            full_description = details.get('full_description', 'N/A')
            full_description = full_description.strip()
            full_description = " ".join(full_description.split())
            full_description = full_description.replace("\n", " ").replace("\r", " ")
            
            permission_type = details.get('permission_type', 'N/A')

            # Capitalize and title-casing
            short_description = short_description.capitalize()
            permission_type = permission_type.title()

            # Create a PermissionADT object
            permission_obj = AndroPermissionADT.AndroPermissionADT(permission, short_description, full_description, permission_type)

            # Clean short description
            cleaned_short_desc = re.sub(' +', ' ', ' '.join(permission_obj.short_desc.splitlines()))
            permission_obj.short_desc = cleaned_short_desc.strip()

            # Add permission object to androguard_data
            androguard_data.add_permission(permission_obj)

def populate_certificate_data(androguard_data, data):
    if 'certificate' in data:
        certificate_data = data['certificate']
        parsed_info = {}

        # Parsing subject information
        subject_info = certificate_data.get('Subject', {})
        parsed_info['Subject'] = {
            'DN': subject_info.get('DN', 'N/A'),
            'C': subject_info.get('C', 'N/A'),
            'CN': subject_info.get('CN', 'N/A')
        }
        
        # Parsing issuer information
        issuer_info = certificate_data.get('Issuer', {})
        parsed_info['Issuer'] = {
            'DN': issuer_info.get('DN', 'N/A'),
            'C': issuer_info.get('C', 'N/A'),
            'CN': issuer_info.get('CN', 'N/A')
        }
        
        # Parsing additional certificate details
        parsed_info['validto'] = certificate_data.get('validto', 'N/A')
        parsed_info['serialnumber'] = certificate_data.get('serialnumber', 'N/A')
        parsed_info['thumbprint'] = certificate_data.get('thumbprint', 'N/A')
        parsed_info['validfrom'] = certificate_data.get('validfrom', 'N/A')
        
        # Setting parsed certificate data
        androguard_data.set_certificate_data(parsed_info)

def populate_intent_filters(androguard_data, data):
    if 'intent_filters' not in data:
        print("No 'intent_filters' key found in the data.")
        return

    for filter_type, components in data['intent_filters'].items():
        if filter_type not in androguard_data.intent_filters.valid_entity_types:
            print(f"Invalid filter type: {filter_type}")
            continue

        for component, filters in components.items():
            # Extract actions and categories
            action = filters.get('action', []) if isinstance(filters.get('action'), list) else []
            category = filters.get('category', []) if isinstance(filters.get('category'), list) else []

            # Store the results in androguard_data
            androguard_data.add_intent_filter(filter_type, component, action, category)