# display_manifest_elements.py

from typing import Dict, List

def print_permissions(permissions: List[Dict]):
    """Print permissions."""
    print("--- Permissions ---")
    if permissions:
        for permission in permissions:
            print(permission.get('name', 'Unknown'))
    else:
        print("No permissions declared.")
    print()

def print_protection_levels(permissions: List[Dict]):
    """Print permissions with protection levels."""
    print("--- Permission Protection Levels ---")
    if permissions:
        for permission in permissions:
            name = permission.get('name', 'Unknown')
            protection_level = permission.get('protectionLevel', 'normal')
            print(f"{name} - Protection Level: {protection_level}")
    else:
        print("No permissions declared.")
    print()

def print_application(application_data: Dict):
    """Print application details."""
    print("--- Application ---")
    if application_data:
        for attribute, value in application_data.items():
            print(f"- {attribute}: {value}")
    else:
        print("No application details.")
    print()

def print_activities(activities: List[Dict]):
    """Print activities."""
    print("--- Activities ---")
    if activities:
        for index, activity in enumerate(activities, start=1):
            print(f"{index}. Activity:")
            for attribute, value in activity.items():
                print(f"    - {attribute}: {value}")
    else:
        print("No activities declared.")
    print()

def print_broadcast_receivers(receivers: List[Dict]):
    """Print broadcast receivers."""
    print("--- Broadcast Receivers ---")
    if receivers:
        for index, receiver in enumerate(receivers, start=1):
            print(f"{index}. Receiver:")
            for attribute, value in receiver.items():
                print(f"    - {attribute}: {value}")
    else:
        print("No broadcast receivers declared.")
    print()

def print_services(services: List[Dict]):
    """Print services."""
    print("--- Services ---")
    if services:
        for index, service in enumerate(services, start=1):
            print(f"{index}. Service:")
            for attribute, value in service.items():
                print(f"    - {attribute}: {value}")
    else:
        print("No services declared.")
    print()

def print_providers(providers: List[Dict]):
    """Print content providers."""
    print("--- Content Providers ---")
    if providers:
        for index, provider in enumerate(providers, start=1):
            print(f"{index}. Provider:")
            for attribute, value in provider.items():
                print(f"    - {attribute}: {value}")
    else:
        print("No content providers declared.")
    print()

def print_intent_filters(intent_filters: List[Dict]):
    """Print intent filters."""
    print("--- Intent Filters ---")
    if intent_filters:
        for index, intent_filter in enumerate(intent_filters, start=1):
            print(f"{index}. Intent Filter:")
            for attribute, value in intent_filter.items():
                print(f"    - {attribute}: {value}")
    else:
        print("No intent filters declared.")
    print()

def print_data(data_list: List[Dict]):
    """Print data."""
    print("--- Data ---")
    if data_list:
        for index, data in enumerate(data_list, start=1):
            print(f"{index}. Data:")
            for attribute, value in data.items():
                print(f"    - {attribute}: {value}")
    else:
        print("No data declared.")
    print()

def print_meta_data(meta_data: List[Dict]):
    """Print meta-data."""
    print("--- Meta-data ---")
    if meta_data:
        for index, data in enumerate(meta_data, start=1):
            print(f"{index}. Meta-data:")
            for attribute, value in data.items():
                print(f"    - {attribute}: {value}")
    else:
        print("No meta-data declared.")
    print()

def print_actions(actions: List[Dict]):
    """Print actions."""
    print("--- Actions ---")
    if actions:
        for action in actions:
            print(action.get('name', 'Unknown'))
    else:
        print("No actions declared.")
    print()

def print_categories(categories: List[Dict]):
    """Print categories."""
    print("--- Categories ---")
    if categories:
        for index, category in enumerate(categories, start=1):
            print(f"{index}. Category:")
            for attribute, value in category.items():
                print(f"    - {attribute}: {value}")
    else:
        print("No categories declared.")
    print()
