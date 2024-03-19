# vt_androguard.py

import re
from . import AndroguardADT, AndroPermissionADT, vt_utils
from utils import logging_utils

def handle_androguard_response(api_response):
    try:
        response_data = api_response.get('data', {})
        if not response_data:
            raise ValueError("No 'data' key in api response.")
        
        data_attributes = response_data.get('attributes', {})
        json_data = data_attributes.get('androguard', None)
        if not json_data:
            return None
        
        #vt_utils.save_json_response(json_data, "JSON_DATA.txt") # DEBUGGING
        androguard = AndroguardADT.AndroguardADT()

        # Populate Hash data
        androguard.set_md5(data_attributes.get('md5', 'N/A'))
        androguard.set_sha1(data_attributes.get('sha1', 'N/A'))
        androguard.set_sha256(data_attributes.get('sha256', 'N/A'))

        populate_manifest_metadata(androguard, json_data)
        populate_manifest_components(androguard, json_data)
        populate_permissions(androguard, json_data)
        #populate_certificate_data(androguard, json_data)
        #populate_intent_filters(androguard, json_data)
        return androguard

    except Exception as e:
        logging_utils.log_error(f"Error in handle_androguard_response(): {e}")
        return None

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
    
    if 'Activities' in data and data['Activities']:
        activities = data['Activities']
        #print(f"Activities {type(activities)} -> {activities}\n") # DEBUGGING
        for a in activities:
            androguard_data.add_activity(a)
    
    if 'Receivers' in data and data['Receivers']:
        receivers = data['Receivers']
        #print(f"Receivers {type(receivers)} -> {receivers}\n") # DEBUGGING
        for r in receivers:
            androguard_data.add_receiver(r)
    
    if 'Providers' in data and data['Providers']:
        providers = data['Providers']
        #print(f"Providers {type(providers)} -> {providers}\n") # DEBUGGING
        for p in providers:
            androguard_data.add_provider(p)
    
    if 'Services' in data and data['Services']:
        services = data['Services']
        #print(f"Services {type(services)} -> {services}\n") # DEBUGGING
        for s in services:
            androguard_data.add_service(s)
    
    if 'Libraries' in data and data['Libraries']:
        libraries = data['Libraries']
        #print(f"Libraries {type(libraries)} -> {libraries}\n") # DEBUGGING
        for l in libraries:
            androguard_data.add_library(l)

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