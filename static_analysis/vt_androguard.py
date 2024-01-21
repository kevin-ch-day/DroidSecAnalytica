# vt_androguard.py

import json

from adt import AndroguardADT
from adt import PermissionADT

def display_androguard_data(attributes):
    androguard_data = parse_androguard_data(attributes)
    if androguard_data:
        print("\n-- Main Analysis --")
        print(f"Main Activity    : {androguard_data.get_main_activity()}")
        print(f"Package          : {androguard_data.get_package()}")
        print(f"Target SDK Version: {androguard_data.get_target_sdk_version()}")

        display_sections(androguard_data)
        display_certificate_details(androguard_data)
        display_permissions(androguard_data.get_permissions())
        display_intent_filters(androguard_data)
    else:
        print("Error: no androguard data found.")

def display_sections(androguard_data):
    sections = ['Activities', 'Receivers', 'Providers', 'Services', 'Libraries']
    for section in sections:
        items = getattr(androguard_data, f'get_{section.lower()}')()
        display_list(section, items)

def display_list(title, items):
    print(f"\n-- {title} --")
    if items:
        for item in items:
            print(f"  {item}")
    else:
        print("  None found")

def display_certificate_details(androguard_data):
    print("\n-- Certificate Details --")
    certificate_data = androguard_data.get_certificate_data()
    if not certificate_data:
        print("  No certificate data available.")
        return

    for key, value in certificate_data.items():
        if isinstance(value, dict):
            print(f"\n{key}:")
            for subkey, subvalue in value.items():
                print(f"  {subkey}: {subvalue}")
        else:
            print(f"{key}: {value}")

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
    parse_basic_data(androguard_data, data)
    parse_permissions(androguard_data, data)
    parse_certificate_data(androguard_data, data)
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
    # Validate the input data
    if not data or 'intent_filters' not in data:
        print("No intent filter data found.")
        return

    if androguard_data and not hasattr(androguard_data, 'add_intent_filter'):
        print("Error: androguard_data does not support adding intent filters.")
        return

    for entity_type, entities in data['intent_filters'].items():
        for entity, filters in entities.items():
            action = filters.get('action', [])
            category = filters.get('category', [])
            
            if androguard_data:
                androguard_data.add_intent_filter(entity_type, entity, action, category)

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
            print(f"    Actions     : {actions}")
            print(f"    Categories  : {categories}")

    print_intent_filters_summary(intent_filters)

def print_intent_filters_summary(intent_filters):
    total_entities = sum(len(entities) for entities in intent_filters.values())
    total_actions = sum(len(filters.get('action', [])) for entities in intent_filters.values() for filters in entities.values())
    total_categories = sum(len(filters.get('category', [])) for entities in intent_filters.values() for filters in entities.values())

    print("\nSummary:")
    print(f"Total Entities : {total_entities}")
    print(f"Total Actions  : {total_actions}")
    print(f"Total Categories: {total_categories}")

    # Additional breakdown by entity type
    for entity_type, entities in intent_filters.items():
        entity_count = len(entities)
        action_count = sum(len(filters.get('action', [])) for filters in entities.values())
        category_count = sum(len(filters.get('category', [])) for filters in entities.values())

        print(f"\n{entity_type} Breakdown:")
        print(f"  Entities    : {entity_count} ({entity_count / total_entities * 100:.2f}%)")
        print(f"  Actions     : {action_count} ({action_count / total_actions * 100:.2f}%)")
        print(f"  Categories  : {category_count} ({category_count / total_categories * 100:.2f}%)")

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