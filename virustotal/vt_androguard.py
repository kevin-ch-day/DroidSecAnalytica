# vt_androguard.py

import re
from . import AndroguardADT, AndroPermissionADT
from utils import logging_utils

def handle_androguard_response(api_response):
    try:
        data = api_response.get('data', {})
        if not data:
            raise ValueError("No 'data' key in api response.")
        
        attributes = data.get('attributes', {})
        return populate_androguard_data(attributes)
    
    except Exception as e:
        logging_utils.log_error(f"Error in handle_androguard_response(): {e}")
        return None

def populate_androguard_data(attributes):
    print("\npopulate_androguard_data()")
    json_data = attributes.get('androguard', None)
    if not json_data:
        return None
    
    #print(json_data) # DEBUGGING
    androguard = AndroguardADT.AndroguardADT()

    # Populate Hash data
    androguard.set_md5(attributes.get('md5', 'N/A'))
    androguard.set_sha1(attributes.get('sha1', 'N/A'))
    androguard.set_sha256(attributes.get('sha256', 'N/A'))

    populate_manifest_metadata(androguard, json_data)
    #populate_manifest_components(androguard, json_data)
    #populate_permissions(androguard, json_data)
    #populate_certificate_data(androguard, json_data)
    #populate_intent_filters(androguard, json_data)
    return androguard

def display_dict_data(data):
    for key in data:
        print(f"{key} -> {data[key]}\n")

def populate_manifest_metadata(androguard_data, data):
    
    if not androguard_data:
        print("Error: androguard_data is None or invalid.")
        return

    try:
        # Setting basic manifest data
        basic_data_settings = [
            ('main_activity', androguard_data.set_main_activity),
            ('Package', androguard_data.set_package),
            ('TargetSdkVersion', androguard_data.set_target_sdk_version)
            ('MinSdkVersion', androguard_data.set_min_sdk_version)
        ]

        for key, setter_function in basic_data_settings:
            if key in data and data[key] is not None:
                setter_function(data[key])

    except Exception as e:
        print(f"Error populate_manifest_metadata(): {str(e)}")

def populate_manifest_components(androguard_data, data):

    if not androguard_data:
        print("Error: androguard_data is None or invalid.")
        return

    try:

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

def populate_permissions(andr_obj, data):
    if 'permission_details' in data:
        permission_details = data['permission_details']

        for permission, details in permission_details.items():
            short_description = details.get('short_description', 'N/A')
            full_description = details.get('full_description', 'N/A')
            full_description = full_description.strip()
            full_description = " ".join(full_description.split())
            full_description = full_description.replace("\n", " ").replace("\r", " ")
            permission_type = details.get('permission_type', 'N/A')

            # Capitalize and title-casing
            short_description = short_description.capitalize()
            permission_type = permission_type.title()

            perm_obj = AndroPermissionADT.AndroPermissionADT(permission, short_description, full_description, permission_type)

            # Clean short description
            cleaned_short_desc = re.sub(' +', ' ', ' '.join(perm_obj.short_desc.splitlines()))
            perm_obj.short_desc = cleaned_short_desc.strip()
            andr_obj.add_permission(perm_obj)

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