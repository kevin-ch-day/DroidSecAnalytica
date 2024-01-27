import re
from . import AndroguardADT, PermissionADT
from utils import logging_utils

def generate_androguard_data(response):
    try:
        data = get_response_data(response)
        attributes = data.get('attributes', {})
        androguard_data = get_androguard_data(attributes)

        if not androguard_data:
            return None

        parsed_data = AndroguardADT.AndroguardADT()
        parse_manifest_data(parsed_data, androguard_data)
        parse_permissions(parsed_data, androguard_data)
        parse_certificate_data(parsed_data, androguard_data)
        parse_intent_filters(parsed_data, androguard_data)

        return parsed_data

    except Exception as e:
        logging_utils.log_error(f"Error in generate_androguard_data: {e}")
        return None

def get_response_data(response):
    data = response.get('data', {})
    if not data:
        raise ValueError("No 'data' key in response.")
    return data

def get_androguard_data(attributes):
    return attributes.get('androguard', None)

def parse_manifest_data(androguard_data, data):
    if not androguard_data:
        print("Error: androguard_data is None or invalid.")
        return

    try:
        basic_data_settings = [
            ('main_activity', androguard_data.set_main_activity),
            ('Package', androguard_data.set_package),
            ('TargetSdkVersion', androguard_data.set_target_sdk_version)
        ]

        for key, setter_function in basic_data_settings:
            if key in data and data[key] is not None:
                setter_function(data[key])

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

    except Exception as e:
        print(f"Error parsing Androguard data: {str(e)}")

def parse_permissions(androguard_data, data):
    if 'permission_details' in data:
        permission_details = data['permission_details']

        for permission, details in permission_details.items():
            # Extract permission details
            short_description = details.get('short_description', 'N/A')
            full_description = details.get('full_description', 'N/A')
            permission_type = details.get('permission_type', 'N/A')

            # Capitalize and title-casing
            short_description = short_description.capitalize()
            permission_type = permission_type.title()

            # Create a PermissionADT object
            permission_obj = PermissionADT.PermissionADT(permission, short_description, full_description, permission_type)

            # Clean short description
            cleaned_short_desc = re.sub(' +', ' ', ' '.join(permission_obj.short_desc.splitlines()))
            permission_obj.short_desc = cleaned_short_desc.strip()

            # Add permission object to androguard_data
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

def parse_certificate_data(androguard_data, data):
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