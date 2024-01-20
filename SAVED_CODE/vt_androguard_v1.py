from tabulate import tabulate

FILE_NAME = 'vt-androguard-results.txt'

def display_data(attributes):
    print("\nAndroguard Data\n")
    data = attributes.get('androguard', 'N/A')

    # Loop I.
    for k in data:
        if k == 'main_activity':
            print("Main activity:", data[k])

        if k == 'Package':
            print("Package:", data[k])

        if k == 'TargetSdkVersion':
            print("TargetSdkVersion:", data[k])

    # Loop II.
    for k in data:
        if k == 'Activities':
            print('\nActivities ')
            for i in data[k]:
                print(" ", i)

        if k == 'Receivers':
            print('\nReceivers')
            for i in data[k]:
                print(" ", i)

        if k == 'Providers':
            print('\nProviders')
            for i in data[k]:
                print(" ", i)

        if k == 'Services':
            print('\nServices')
            for i in data[k]:
                print(" ", i)

        if k == 'Libraries':
            print('\nLibraries')
            for i in data[k]:
                print(" ", i)

        if k == 'certificate':
            cert_data = parse_certificate(data[k])
            display_certificate_info(cert_data)

        if k == 'intent_filters':
            intent_data = parse_intent_filters(data[k])
            print_intent_filters(intent_data)

        if k == 'permission_details':
            permission_data = parse_permission_details(data[k])
            print_permission_details(permission_data)

def boxed_header(title):
    """Creates a boxed header for a section."""
    line = "-" * len(title)
    return f"+{line}+\n|{title}|\n+{line}+\n"

def write_main_attributes(file, data):
    """Writes the main attributes section."""
    file.write(boxed_header("Main Attributes"))
    for key in ['main_activity', 'Package', 'TargetSdkVersion']:
        if key in data:
            file.write(f"{key.replace('_', ' ').title()}: {data[key]}\n")
    file.write("\n")

def write_nested_data_sections(file, data):
    """Writes nested data sections like Activities, Receivers, etc."""
    for key in ['Activities', 'Receivers', 'Providers', 'Services', 'Libraries']:
        if key in data:
            file.write(boxed_header(key))
            for item in data[key]:
                file.write(f"  - {item}\n")
            file.write("\n")

def write_certificate_details(file, data):
    """Writes the certificate details section."""
    if 'certificate' in data:
        cert_data = parse_certificate(data['certificate'])
        file.write(boxed_header("Certificate Details"))
        for k, v in cert_data.items():
            file.write(f"{k.title().replace('_', ' ')}: {v}\n")
        file.write("\n")

def write_intent_filters(file, data):
    """Writes the intent filters section."""
    if 'intent_filters' in data:
        intent_data = parse_intent_filters(data['intent_filters'])
        file.write(boxed_header("Intent Filters"))
        for activity, filters in intent_data.items():
            file.write(f"Activity: {activity}\n")
            for filter_type, values in filters.items():
                file.write(f"  {filter_type.title()}: {', '.join(values)}\n")
        file.write("\n")

def write_permissions_data(file, data):
    """Writes the permissions data section."""
    if 'permission_details' in data:
        permission_data = parse_permission_details(data['permission_details'])
        if permission_data:
            file.write(boxed_header("Permissions Data"))
            file.write(f"Total Permissions: {len(permission_data)}\n\n")
            for i, permission in enumerate(permission_data, 1):
                permission_name, short_desc, long_desc, perm_type = permission
                file.write(f"[{i}] {permission_name}\n")
                file.write(f"    Description: {short_desc}\n")
                file.write(f"    Type: {perm_type}\n\n")
        else:
            file.write("No permission data available.\n\n")

def save_data_to_file(attributes):
    with open(FILE_NAME, 'w', encoding='utf-8') as file:
        file.write("Android Malware Analysis Report\n")
        file.write("=" * 80 + "\n\n")
        data = attributes.get('androguard', None)

        if data:
            write_main_attributes(file, data)
            write_nested_data_sections(file, data)
            write_certificate_details(file, data)
            write_intent_filters(file, data)
            write_permissions_data(file, data)
        else:
            file.write("No Androguard data available.\n")

def parse_certificate(certificate_data):
    parsed_info = {}
    
    # Extract Subject information
    subject_info = certificate_data.get('Subject', {})
    parsed_info['Subject'] = {
        'DN': subject_info.get('DN', 'N/A'),
        'C': subject_info.get('C', 'N/A'),
        'CN': subject_info.get('CN', 'N/A')
    }
    
    # Extract Issuer information
    issuer_info = certificate_data.get('Issuer', {})
    parsed_info['Issuer'] = {
        'DN': issuer_info.get('DN', 'N/A'),
        'C': issuer_info.get('C', 'N/A'),
        'CN': issuer_info.get('CN', 'N/A')
    }
    
    # Extract other certificate details
    parsed_info['validto'] = certificate_data.get('validto', 'N/A')
    parsed_info['serialnumber'] = certificate_data.get('serialnumber', 'N/A')
    parsed_info['thumbprint'] = certificate_data.get('thumbprint', 'N/A')
    parsed_info['validfrom'] = certificate_data.get('validfrom', 'N/A')
    
    return parsed_info

def display_certificate_info(parsed_certificate):
    headers = ["Field", "Value"]
    print("\nCertificate Information:")
    data = [
        ["Subject", parsed_certificate['Subject']['CN']],
        ["Issuer", parsed_certificate['Issuer']['CN']],
        ["Valid From", parsed_certificate['validfrom']],
        ["Valid To", parsed_certificate['validto']],
        ["Serial Number", parsed_certificate['serialnumber']],
        ["Thumbprint", parsed_certificate['thumbprint']]
    ]
    print(tabulate(data, headers, tablefmt="fancy_grid"))

def parse_intent_filters(intent_filters_data):
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

def print_intent_filters(parsed_data):
    print("\nIntent Filters:")
    
    # Print Activities
    activities = parsed_data.get('Activities', {})
    if activities:
        print("\nActivities:")
        for activity, filters in activities.items():
            print(f"Activity: {activity}")
            print(f"  Action:")
            for action in filters['action']:
                print(f"    {action}")
            print(f"  Category:")
            for category in filters['category']:
                print(f"    {category}")

    # Print Receivers
    receivers = parsed_data.get('Receivers', {})
    if receivers:
        print("\nReceivers:")
        for receiver, filters in receivers.items():
            print(f"Receiver: {receiver}")
            print(f"  Action(s):")
            for index, action in enumerate(filters['action'], start=1):
                print(f"    [{index}] {action}")
            print()

def parse_permission_details(permission_details):
    parsed_data = []
    for permission, details in permission_details.items():
        short_description = details.get('short_description', 'N/A')
        full_description = details.get('full_description', 'N/A')
        permission_type = details.get('permission_type', 'N/A')
        parsed_data.append([permission, short_description.capitalize(), full_description, permission_type.title()])
    return parsed_data

def print_permission_details(permission_data):
    if not permission_data:
        print("No permission details available.")
        return
    headers = ["Permission", "Short Description", "Full Description", "Permission Type"]
    print("\n" + tabulate(permission_data, headers, tablefmt="fancy_grid"))

def write_intent_filters_to_file(intent_data):
    with open(FILE_NAME, 'a', encoding='utf-8') as file:
        file.write("\nIntent Filters:\n")
        
        # Print Activities
        activities = intent_data.get('Activities', {})
        if activities:
            file.write("\nActivities:\n")
            for activity, filters in activities.items():
                file.write(f"Activity: {activity}\n")
                file.write(f"  Action:\n")
                for action in filters['action']:
                    file.write(f"    {action}\n")
                file.write(f"  Category:\n")
                for category in filters['category']:
                    file.write(f"    {category}\n")

        # Print Receivers
        receivers = intent_data.get('Receivers', {})
        if receivers:
            file.write("\nReceivers:\n")
            for receiver, filters in receivers.items():
                file.write(f"Receiver: {receiver}\n")
                file.write(f"  Action:\n")
                if filters['action'] == 1:
                    for action in filters['action']:
                        file.write(f"    {action}\n")
                else:
                    cnt = 1
                    for action in filters['action']:
                        file.write(f"    [{cnt}] {action}\n")
                        cnt += 1
                file.write("\n")

def write_certificate_info_to_file(parsed_certificate):
    headers = ["Field", "Value"]
    with open(FILE_NAME, 'a', encoding='utf-8') as file:
        file.write("\nCertificate Information:\n")
        data = [
            ["Subject", parsed_certificate['Subject']['CN']],
            ["Issuer", parsed_certificate['Issuer']['CN']],
            ["Valid From", parsed_certificate['validfrom']],
            ["Valid To", parsed_certificate['validto']],
            ["Serial Number", parsed_certificate['serialnumber']],
            ["Thumbprint", parsed_certificate['thumbprint']]
        ]
        table = tabulate(data, headers, tablefmt="fancy_grid")
        file.write(table)
