from utils import logging_utils
from . import vt_utils

def display_sections(androguard_data):
    try:
        sections = ['Activities', 'Receivers', 'Providers', 'Services', 'Libraries']
        for section in sections:
            items = getattr(androguard_data, f'get_{section.lower()}')()
            vt_utils.display_list(section, items)
    
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
            print("  No certificate data available.")
            return
        vt_utils.display_dict(certificate_data.items())
    except Exception as e:
        logging_utils.log_error(f"Error processing certificate details: {str(e)}")

def display_permissions(permissions):
    try:
        print("\nPermissions:")
        if not permissions:
            logging_utils.log_warning("No permissions data provided to display.")
            return

        max_name_width = 50  # Maximum width for permission names
        max_type_width = 20  # Maximum width for permission types

        header = "NAME".ljust(max_name_width) + "Type".ljust(max_type_width) + "Description"
        print(header)
        print("-" * len(header))  # Print a separator line

        for perm in permissions:
            display_name = (perm.name[:max_name_width - 3] + '...') if len(perm.name) > max_name_width else perm.name
            display_type = (perm.permission_type[:max_type_width - 3] + '...') if len(perm.permission_type) > max_type_width else perm.permission_type
            print(f"{display_name.ljust(max_name_width)}{display_type.ljust(max_type_width)}{perm.short_desc}")
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

    for entity_type, entities in intent_filters.items():
        entity_count = len(entities)
        action_count = sum(len(filters.get('action', [])) for filters in entities.values())
        category_count = sum(len(filters.get('category', [])) for filters in entities.values())

        print(f"\n{entity_type} Breakdown:")
        print(f"  Entities    : {entity_count} ({entity_count / total_entities * 100:.2f}%)")
        print(f"  Actions     : {action_count} ({action_count / total_actions * 100:.2f}%)")
        print(f"  Categories  : {category_count} ({category_count / total_categories * 100:.2f}%)")

def display_main_activity(androguard_data):
    print("\n-- Main Analysis --")
    print(f"Main Activity     : {androguard_data.get_main_activity()}")
    print(f"Package           : {androguard_data.get_package()}")
    print(f"Target SDK Version: {androguard_data.get_target_sdk_version()}")