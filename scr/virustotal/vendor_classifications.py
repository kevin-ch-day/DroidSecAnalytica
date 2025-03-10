# vendor_classifications.py

from typing import Tuple, Dict

from database import db_update_records

def analyze_classifications(df):
    results = {}

    print("=" * 60)

    # Process each row for vendor-specific data and update analysis results
    for index, row in df.iterrows():
        #print(row)
        
        apk_id = row['APK ID']
        print(f"{'Vendor':<25}{'Classification'}")
        print(f"{'-' * 60}")

        results[apk_id] = {}

        # Parsing AhnLab_V3 classification
        ahnlab_classification = row.get('AhnLab_V3', "N/A")
        print(f"{'AhnLab_V3:':<25}{ahnlab_classification}")
        results[apk_id]['AhnLab_V3'] = determine_ahnlab_v3_classification(ahnlab_classification)

        # Parsing Alibaba classification
        alibaba_classification = row.get('Alibaba', "N/A")
        print(f"{'Alibaba:':<25}{alibaba_classification}")
        results[apk_id]['Alibaba'] = determine_alibaba_classification(alibaba_classification)

        # Parsing Ikarus classification
        ikarus_classification = row.get('Ikarus', "N/A")
        print(f"{'Ikarus:':<25}{ikarus_classification}")
        results[apk_id]['Ikarus'] = determine_ikarus_classification(ikarus_classification)

        # Parsing Kaspersky classification
        kaspersky_classification = row.get('Kaspersky', "N/A")
        print(f"{'Kaspersky:':<25}{kaspersky_classification}")
        results[apk_id]['Kaspersky'] = determine_kaspersky_classification(apk_id, kaspersky_classification)

        # Parsing Microsoft classification
        microsoft_classification = row.get('Microsoft', "N/A")
        print(f"{'Microsoft:':<25}{microsoft_classification}")
        results[apk_id]['Microsoft'] = determine_microsoft_classification(microsoft_classification)

        # Parsing ZoneAlarm classification
        zonealarm_classification = row.get('ZoneAlarm', "N/A")
        print(f"{'ZoneAlarm:':<25}{zonealarm_classification}")
        results[apk_id]['ZoneAlarm'] = determine_zonealarm_classification(apk_id, zonealarm_classification)

    return results

def determine_ahnlab_v3_classification(classification):
    if classification:
        return parse_ahnlab_v3_classification(classification)
    else:
        return {
            'malware_type': 'Unknown',
            'platform': 'Unknown',
            'family': 'Unknown',
            'variant': 'Unknown'
        }

def determine_alibaba_classification(classification):
    if classification:
        return parse_alibaba_classification(classification)
    else:
        return {
            'ability': 'Unknown',
            'platform': 'Unknown',
            'family': 'Unknown',
            'variant': 'Unknown',
            'malware_type': 'Unknown'
        }

def determine_ikarus_classification(classification):
    if classification:
        return parse_ikarus_classification(classification)
    else:
        return {
            'malware_type': 'Unknown',
            'ability': 'Unknown',
            'platform': 'Unknown',
            'family': 'Unknown'
        }

def determine_kaspersky_classification(apk_id, classification):
    if classification:
        return parse_kaspersky_classification(apk_id, classification)
    else:
        return {
            'malware_type': 'Unknown',
            'platform': 'Unknown',
            'family': 'Unknown',
            'variant': 'Unknown'
        }

def determine_microsoft_classification(classification):
    if classification:
        return parse_microsoft_classification(classification)
    else:
        return {
            'malware_type': 'Unknown',
            'platform': 'Unknown',
            'family': 'Unknown',
            'variant': 'Unknown'
        }

def determine_zonealarm_classification(apk_id, classification):
    if classification:
        return parse_zonealarm_classification(apk_id, classification)
    else:
        return {
            'malware_type': 'Unknown',
            'ability': 'Unknown',
            'platform': 'Unknown',
            'family': 'Unknown',
            'variant': 'Unknown'
        }

def parse_ahnlab_v3_classification(classification):
    try:
        malware_type, platform_family_variant = classification.split('/', 1)
        platform, family_variant = platform_family_variant.split('.', 1)
        family, variant = family_variant.split('.', 1)

        # Return the parsed components in a dictionary
        return {
            'malware_type': malware_type,
            'platform': platform,
            'family': family,
            'variant': variant
        }
    
    except ValueError as e:
        print(f"Error parsing classification '{classification}': {e}")
        return {
            'malware_type': 'Unknown',
            'platform': 'Unknown',
            'family': 'Unknown',
            'variant': 'Unknown'
        }


def parse_alibaba_classification(classification):
    # Sanitize the input by stripping whitespace
    classification = classification.strip()

    # Initialize variables
    ability = 'Unknown'
    platform = 'Unknown'
    family = 'Unknown'
    variant = 'Unknown'
    malware_type = 'Unknown'

    # Split the classification string by the first colon, if it exists
    parts = classification.split(':', 1)
    if len(parts) == 2:
        malware_type, rest = parts[0], parts[1]
    else:
        rest = classification

    # Split the rest into platform and family, and optionally variant
    platform_family, _, variant = rest.partition('.')
    if '/' in platform_family:
        platform, family = platform_family.split('/', 1)
    else:
        family = platform_family

    # Determine ability from malware type
    if malware_type.startswith('Trojan'):
        ability = malware_type.split('Trojan', 1)[1]
        malware_type = 'Trojan'
    elif malware_type.startswith('Backdoor'):
        ability = 'Backdoor'
        malware_type = 'Unknown'
    elif malware_type.startswith('TrojanSpy'):
        ability = 'Spy'
    elif malware_type.startswith('TrojanBanker'):
        ability = 'Banker'
    elif malware_type.startswith('TrojanDownloader'):
        ability = 'Downloader'

    # Return the parsed components in a dictionary
    return {
        'ability': ability,
        'platform': platform,
        'family': family,
        'variant': variant,
        'malware_type': malware_type
    }

def parse_ikarus_classification(classification):
    # Define the main malware types
    malware_type = ['Trojan', 'Backdoor', 'Worm', 'Virus']
    
    # Split the classification string by '.'
    parts = classification.split('.')
    
    # Initialize dictionary to store classification parts
    parsed_classification = {
        'malware_type': 'Unknown',
        'ability': 'Unknown',
        'platform': 'Unknown',
        'family': 'Unknown'
    }
    
    # Check if the first part is a known main malware type
    if parts[0] in malware_type:
        parsed_classification['malware_type'] = parts[0]
        remaining_parts = '.'.join(parts[1:])

    else:
        remaining_parts = classification

    # Split the remaining parts by the platform designator 'AndroidOS'
    if 'AndroidOS' in remaining_parts:
        action_platform, family = remaining_parts.split('AndroidOS.', 1)
        # Further split the action type if it's prefixed by the main type
        if '-' in action_platform:
            action_type = action_platform.split('-', 1)[1]
        else:
            action_type = "Unknown"

        # Assign the extracted parts to the dictionary
        parsed_classification['ability'] = action_type
        parsed_classification['platform'] = 'Android'
        parsed_classification['family'] = family

    return parsed_classification

def parse_kaspersky_classification(apk_id, classification: str) -> Tuple[Dict[str, str], bool]:
    """
    Parses the Kaspersky classification string and returns the classification details and a boolean
    indicating if the 'Not-a-virus' prefix was present.
    """

    # Check for the 'Not-a-virus' prefix
    is_not_a_virus = "not-a-virus" in classification
    if is_not_a_virus:
        classification = classification.replace("not-a-virus:", "").strip()
        db_update_records.update_kaspersky_not_a_virus(apk_id, True)
    
    if "HEUR:" in classification:
        classification = classification.replace("HEUR:", "").strip()

    # Initialize default values for the parsed classification
    malware_type = ability = platform = family = variant = "Unknown"
    parsed_classification = {
        'malware_type': malware_type,
        'ability': ability,
        'platform': platform,
        'family': family,
        'variant': variant
    }

    # Split the classification by periods to separate parts
    parts = classification.split('.')

    # If parts are fewer than expected, return the default classification
    if len(parts) < 3:
        print(f"[ERROR] Unexpected classification structure: {classification}")
        return parsed_classification

    try:
        # Parse the classification string into its components
        if '-' in parts[0]:
            malware_type, ability = parts[0].split('-')
        else:
            ability = parts[0]

        platform = parts[1] if len(parts) > 1 else "Unknown"
        family = parts[2] if len(parts) > 2 else "Unknown"
        variant = parts[3] if len(parts) > 3 else "Unknown"

        parsed_classification = {
            'malware_type': malware_type,
            'ability': ability,
            'platform': platform,
            'family': family,
            'variant': variant
        }

    except Exception as e:
        print(f"[ERROR] Failed to parse classification '{classification}': {e}")
    
    return parsed_classification

def parse_microsoft_classification(classification):
    # Split the classification by colon to separate type and the rest of the string
    parts = classification.split(':')
    if len(parts) != 2:
        return None

    malware_type = parts[0].strip()
    remaining = parts[1].strip()

    # Split the remaining string by slash to separate platform and family/variant
    platform_family_variant = remaining.split('/')
    if len(platform_family_variant) != 2:
        return None

    platform_family = platform_family_variant[0].strip()
    variant = platform_family_variant[1].strip()

    # Separate family and variant if present
    family_parts = platform_family.split('.')
    family = family_parts[0] if family_parts else 'Unknown'

    return {
        'malware_type': malware_type,
        'platform': platform_family,
        'family': family,
        'variant': variant
    }

def parse_zonealarm_classification(apk_id, classification):
    # Check for the 'Not-a-virus' prefix
    is_not_a_virus = "not-a-virus" in classification
    if is_not_a_virus:
        classification = classification.replace("not-a-virus:", "").strip()
        db_update_records.update_zoneAlarm_not_a_virus(apk_id, True)

    # Remove 'HEUR:' prefix if present
    classification = classification.replace('HEUR:', '')
    
    # Default values
    malware_type = "Unknown"
    ability = "Unknown"
    platform = "Unknown"
    family = "Unknown"
    variant = "Unknown"
    
    # Split the classification by '.' to get the main parts
    parts = classification.split('.')

    # Check if the type is included; if not, the first part is the ability
    if '-' in parts[0]:
        # Type and ability are present
        type_ability, platform_family_variant = parts[0], parts[1:]
        malware_type, ability = type_ability.split('-')
    else:
        # Only ability is present
        ability, platform_family_variant = parts[0], parts[1:]

    # Extract platform, family, and variant
    if len(platform_family_variant) >= 2:
        platform = platform_family_variant[0]
        family = platform_family_variant[1]
        if len(platform_family_variant) == 3:
            variant = platform_family_variant[2]

    return {
        'malware_type': malware_type,
        'ability': ability,
        'platform': platform,
        'family': family,
        'variant': variant
    }

def count_attribute_occurrences(vendors_info, attributes_counter):
    for vendor, attributes in vendors_info.items():
        #print(f"\n  Processing vendor: {vendor}") # DEBUGGING
        for attribute, value in attributes.items():
            if value != 'Unknown' and attribute in attributes_counter:
                attributes_counter[attribute][value] = attributes_counter[attribute].get(value, 0) + 1
                #print(f"    Attribute '{attribute}' with value '{value}' count is now {attributes_counter[attribute][value]}") # DEBUGGING
    return attributes_counter

def determine_consensus_attributes(attributes_counter):
    consensus_attributes = {}
    for attribute, counts in attributes_counter.items():
        if counts:
            consensus_value = max(counts, key=counts.get)
            consensus_attributes[attribute] = consensus_value
            #print(f"  Consensus for '{attribute}' is '{consensus_value}' with {counts[consensus_value]} occurrences") # DEBUGGING
    return consensus_attributes

def create_classification_label(data):
    label_parts = []
    if 'platform' in data:
        label_parts.append(data['platform'])
    if 'malware_type' in data:
        label_parts.append(data['malware_type'])
    if 'family' in data and 'variant' in data:
        label_parts.append(f"{data['family']}-{data['variant']}")
    if 'ability' in data:
        label_parts.append(f"[{data['ability']}]")

    label = ':'.join(label_parts) if label_parts else 'Undetermined'
    return label

def data_classification(data):
    new_label = None
    attributes_counter = {
            'malware_type': {},
            'ability': {},
            'platform': {},
            'family': {},
            'variant': {}
        }

    for vendors_info in data.items():
        vendors_info_dict = {vendors_info[0]: vendors_info[1]}
        attributes_counter = count_attribute_occurrences(vendors_info_dict, attributes_counter)
        consensus_attributes = determine_consensus_attributes(attributes_counter)
        new_label = create_classification_label(consensus_attributes)

    return new_label