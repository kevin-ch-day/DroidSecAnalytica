
from utils import logging_utils

logger = logging_utils.get_logger(__name__)

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
    
    except Exception:
        logger.exception("Error processing sections")

def display_certificate_details(androguard_data):
    try:
        print("\n-- Certificate Details --")
        if not androguard_data or not hasattr(androguard_data, 'get_certificate_data'):
            logger.error("Invalid or no androguard data provided for certificate details.")
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

    except Exception:
        logger.exception("Error processing certificate details")

def display_permissions(androguard_data):
    try:
        permissions = androguard_data.get_permissions()
        print("\n-- Permissions --")
        if not permissions:
            logger.warning("No permissions data provided to display.")
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

    except Exception:
        logger.exception("Error processing permissions")

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

    display_intent_filters_summary(intent_filters)

def display_intent_filters_summary(intent_filters):
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

def display_summary_statistics(report_data):
    if "Analysis Result" in report_data:
        summary_statistics = report_data["Analysis Result"].get("summary_statistics", {})
        print("\nSummary Statistics:")
        for key, value in summary_statistics.items():
            print(f"{key}:".ljust(25), value)
    else:
        print("Summary statistics not available.")

def display_detection_breakdown(report_data):
    if "Analysis Result" in report_data:
        detection_breakdown = report_data["Analysis Result"].get("engine_detection", [])
        if detection_breakdown:
            print("\nDetection Breakdown:")
            for item in detection_breakdown:
                engine_name, detection_label = item[0], item[1]
                print(f"{engine_name.ljust(30)}: {detection_label}")
        else:
            print("Detection breakdown not available.")
    else:
        print("Detection breakdown not available.")
