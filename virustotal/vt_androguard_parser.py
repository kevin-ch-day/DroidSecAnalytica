from utils import logging_utils
from . import vt_utils, PermissionADT

def parse_basic_data(androguard_data, data):
    try:
        for key, setter_function in [
            ('main_activity', androguard_data.set_main_activity),
            ('Package', androguard_data.set_package),
            ('TargetSdkVersion', androguard_data.set_target_sdk_version)]:
            vt_utils.set_data_if_key_exists(key, setter_function, data)

        for key, add_function in [
            ('Activities', androguard_data.add_activity),
            ('Receivers', androguard_data.add_receiver),
            ('Providers', androguard_data.add_provider),
            ('Services', androguard_data.add_service),
            ('Libraries', androguard_data.add_library)]:
            if key in data:
                add_function(data[key])

        # Special handling for intent filters
        if 'IntentFilters' in data:
            for entity_type, entity_data in data['IntentFilters'].items():
                for entity, filters in entity_data.items():
                    for filter_data in filters:
                        action = filter_data.get('Action', '')
                        category = filter_data.get('Category', '')
                        androguard_data.add_intent_filter(entity_type, entity, action, category)
                        print(f"Added IntentFilter - Entity Type: {entity_type}, Entity: {entity}, Action: {action}, Category: {category}")

    except Exception as e:
        # Handle the exception here (e.g., print an error message or log it)
        print(f"Error parsing Androguard data: {str(e)}")
        logging_utils.log_error(f"Error parsing Androguard data: {str(e)}")

def parse_permissions(androguard_data, data):
    if 'permission_details' in data:
        permission_data = parse_permission_details(data['permission_details'])
        for permission in permission_data:
            p = PermissionADT.PermissionADT(*permission)
            androguard_data.add_permission(p)

def parse_intent_filters(androguard_data, data):
    try:
        if not data or 'intent_filters' not in data:
            print("No intent filter data found.")
            return

        if not androguard_data:
            print("Error: androguard_data is not provided.")
            return

        if not hasattr(androguard_data, 'add_intent_filter'):
            print("Error: androguard_data does not support adding intent filters.")
            return

        for entity_type, entities in data['intent_filters'].items():
            for entity, filters in entities.items():
                action = filters.get('action', [])
                category = filters.get('category', [])
                
                # Check if the entity type is valid (e.g., 'Services')
                if entity_type not in ['Services', 'OtherValidEntityTypes']:
                    print(f"Warning: Invalid entity type '{entity_type}' in intent filter data.")
                    continue
                
                # Add the intent filter to androguard_data
                androguard_data.add_intent_filter(entity_type, entity, action, category)

    except Exception as e:
        # Handle the exception here (e.g., print an error message or log it)
        print(f"Error parsing intent filters: {str(e)}")

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