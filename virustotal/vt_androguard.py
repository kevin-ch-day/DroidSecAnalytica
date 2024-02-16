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
    populate_manifest_components(androguard, json_data)
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
    
    main_activity = data['main_activity']
    package = data['Package']
    targetSdkVersion= data['TargetSdkVersion']
    minSdkVersion = data['MinSdkVersion']

    androguard_data.set_main_activity(main_activity)
    androguard_data.set_package(package)
    androguard_data.set_target_sdk_version(targetSdkVersion)
    androguard_data.set_min_sdk_version(minSdkVersion)

def populate_manifest_components(androguard_data, data):
    if not androguard_data:
        print("Error: androguard_data is None or invalid.")
        return
    
    display_dict_data(data)
    print()

    component_types = ['Activities', 'Receivers', 'Providers', 'Services', 'Libraries']

    for component_type in component_types:
        # Safely get the component data, defaulting to None if not found
        component_data = data.get(component_type)

        # Only proceed if component_data is not None and not empty
        if component_data:
            
            # Construct the method name based on the component_type
            method_name = f'set_{component_type.lower()}'
            
            # Check if the androguard_data object has the method
            if hasattr(androguard_data, method_name):
                getattr(androguard_data, method_name)(component_data)
                print(f"{component_type} {type(component_data)} -> {component_data}\n")
            else:
                print(f"Warning: androguard_data does not have a method to handle {component_type}")
        else:
            print(f"{component_type} is empty or not present.")


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