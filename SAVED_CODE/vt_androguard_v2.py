# vt_androguard.py

import json

import AndroguardADT
import PermissionADT
import IntentFilterADT

def display_androguard_data(attributes):
    androguard_data = parse_androguard_data(attributes)
    if androguard_data:
        print("\nMain Activity:", androguard_data.get_main_activity())
        print("Package:", androguard_data.get_package())
        print("Targetsdkversion:", androguard_data.get_target_sdk_version())

        display_list("Activities", androguard_data.get_activities())
        display_list("Receivers", androguard_data.get_receivers())
        display_list("Providers", androguard_data.get_providers())
        display_list("Services", androguard_data.get_services())
        display_list("Libraries", androguard_data.get_libraries())

        print("\nCertificate Details:")
        display_dict(androguard_data.get_certificate_data())

        display_permissions(androguard_data.get_permissions())

        # display_intent_filters()

    else:
        print("Error: no androguard data found.")

def display_permissions(permissions):
    print("\nPermissions:")
    max_name_width = 50  # Maximum width for permission names
    max_type_width = 20  # Maximum width for permission types

    header = "NAME".ljust(max_name_width) + "Type".ljust(max_type_width) + "Description"
    print(header)
    print("-" * len(header))  # Print a separator line

    if permissions:
        for perm in permissions:
            # Truncate the permission name and type if they are too long
            display_name = (perm.name[:max_name_width - 3] + '...') if len(perm.name) > max_name_width else perm.name
            display_type = (perm.permission_type[:max_type_width - 3] + '...') if len(perm.permission_type) > max_type_width else perm.permission_type
            print(f"{display_name.ljust(max_name_width)}{display_type.ljust(max_type_width)}{perm.short_desc}")
    else:
        print("  None found")

def display_list(title, items):
    print(f"\n{title}:")
    if items:
        for item in items:
            print(f"  {item}")
    else:
        print("  None found")

def display_dict(data):
    if data:
        for k, v in data.items():
            if isinstance(v, dict):
                print(f"  {k}:")
                for sub_key, sub_val in v.items():
                    print(f"    {sub_key}: {sub_val}")
            else:
                print(f"  {k}: {v}")
    else:
        print("  None found")

def export_data_to_json(androguard_data, filename='androguard_data.json'):
    with open(filename, 'w') as file:
        json.dump(androguard_data.to_dict(), file, indent=4)

def parse_androguard_data(attributes):
    data = attributes.get('androguard', None)
    if not data:
        return None

    androguard_data = AndroguardADT.AndroguardADT()
    #parse_basic_data(androguard_data, data)
    #parse_permissions(androguard_data, data)
    #parse_certificate_data(androguard_data, data)
    parse_intent_filters(androguard_data, data)
    return androguard_data

def parse_basic_data(androguard_data, data):
    for key, setter_function in [
        ('main_activity', androguard_data.set_main_activity),
        ('Package', androguard_data.set_package),
        ('TargetSdkVersion', androguard_data.set_target_sdk_version)]:
        set_data_if_key_exists(key, setter_function, data)

    for key, add_function in [
        ('Activities', androguard_data.add_activity),
        ('Receivers', androguard_data.add_receiver),
        ('Providers', androguard_data.add_provider),
        ('Services', androguard_data.add_service),
        ('Libraries', androguard_data.add_library)]:
        add_items_to_list_if_key_exists(key, add_function, data)

def parse_permissions(androguard_data, data):
    if 'permission_details' in data:
        permission_data = parse_permission_details(data['permission_details'])
        for permission in permission_data:
            p = PermissionADT.PermissionADT(*permission)
            androguard_data.add_permission(p)

def parse_intent_filters(androguard_data, data):
    if 'intent_filters' in data:
        for entity_type, entities in data['intent_filters'].items():
            for entity, filters in entities.items():
                action = filters.get('action', [])
                category = filters.get('category', [])
                androguard_data.add_intent_filter(entity_type, entity, action, category)

    print("Parsed Intent Filters:")
    for entity_type, entities in androguard_data.get_all_intent_filters().items():
        print(f"{entity_type}:")
        for entity, filters in entities.items():
            print(f"  {entity}: {filters}")
    exit()

def get_intent_filters(intent_filters_data):
    parsed_data = {}

    # Parse Activities
    activities = intent_filters_data.get('Activities', {})
    parsed_activities = {}
    for activity, filters in activities.items():
        action = filters.get('action', [])
        category = filters.get('category', [])
        parsed_activities[activity] = {'action': action, 'category': category}
    
    parsed_data['Activities'] = parsed_activities

    # Parse Receivers
    receivers = intent_filters_data.get('Receivers', {})
    parsed_receivers = {}
    for receiver, filters in receivers.items():
        action = filters.get('action', [])
        parsed_receivers[receiver] = {'action': action}
    
    parsed_data['Receivers'] = parsed_receivers

    return parsed_data

def parse_certificate_data(androguard_data, data):
    if 'certificate' in data:
        cert_data = parse_certificate(data['certificate'])
        androguard_data.set_certificate_data(cert_data)

def set_data_if_key_exists(key, setter_function, data):
    if key in data:
        setter_function(data[key])

def add_items_to_list_if_key_exists(key, add_function, data):
    if key in data:
        for item in data[key]:
            add_function(item)

def display_intent_filters(intent_filters):
    for k in intent_filters:
        print(intent_filters[k])
        for index in intent_filters[k]:
            print(index)

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