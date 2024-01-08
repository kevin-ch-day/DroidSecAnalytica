#!/usr/bin/env python3

import re
import requests
import textwrap
import datetime
from bs4 import BeautifulSoup as Soup
from bs4 import element
from typing import Dict, Tuple

ANDROID_PERMISSION_DOCS_URL = 'https://developer.android.com/reference/android/Manifest.permission'

def fetch_html(url: str) -> str:
    """Fetch HTML content from a given URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return ""

def parse_permission_data(html_content: str) -> Dict[str, Dict[str, str]]:
    content = Soup(html_content, 'html.parser')
    permissions = {}

    permission_divs = content.find_all('div', {'data-version-added': re.compile(r'\d*')})
    for pd in permission_divs:
        permission_name = pd.find('h3').contents[0]
        if permission_name in ['Constants', 'Manifest.permission']:
            continue

        # Extract API level at which permission was added
        added_in_api = pd.get('data-version-added', 'Unknown')

        # Check if the permission is deprecated
        deprecated = 'Yes' if pd.get('data-deprecated', None) else 'No'

        description_text, constant_value, extracted_protection_level = parse_description(pd)

        permissions[permission_name] = {
            'Protection Level': extracted_protection_level if extracted_protection_level else 'normal',
            'Added in API': added_in_api,
            'Deprecated': deprecated,
            'Description': description_text,
            'Constant Value': constant_value,
            # Add more fields here
        }

    return permissions

def parse_description(permission_div: element.Tag) -> Tuple[str, str, str]:
    """Parse description from permission div tag."""
    description = []
    constant_value = ""
    extracted_protection_level = None

    for content in permission_div.find('p').contents:
        text = str(content).strip() if isinstance(content, element.NavigableString) else content.text.strip()
        text = re.sub(r'\s+', ' ', text)

        if 'Constant Value:' in text:
            constant_value_match = re.search(r'Constant Value: (.+)', text)
            if constant_value_match:
                constant_value = constant_value_match.group(1)
                constant_value = constant_value.replace('"', '')
            text = text.replace(f"Constant Value: {constant_value}", "").strip()

        protection_level_match = re.search(r'Protection level: (.+?)(?:\s|$)', text)
        if protection_level_match:
            extracted_protection_level = protection_level_match.group(1)
            text = text.replace(f"Protection level: {extracted_protection_level}", "").strip()

        description.append(text)

    return ' '.join(description).strip(), constant_value, extracted_protection_level

def write_permissions_to_file(permissions: Dict[str, Dict[str, str]], filename: str):
    """Write permissions data to a file with improved formatting and metadata."""
    current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source_url = ANDROID_PERMISSION_DOCS_URL

    with open(filename, 'w') as file:
        file.write(f"Permissions Data Extracted On: {current_datetime}\n")
        file.write(f"Source URL: {source_url}\n")
        file.write(f"Total Permissions: {len(permissions)}\n\n")

        for permission, details in permissions.items():
            file.write(f"--- Permission: {permission} ---\n")
            for key in ['Protection Level', 'Added in API', 'Deprecated']:
                file.write(f"{key.ljust(20)}: {details.get(key, 'N/A')}\n")

            # Wrap description text at 80 characters
            description = details.get('Description', 'N/A')
            wrapped_description = textwrap.fill(description, width=80)
            file.write(f"Description: {wrapped_description}\n")

            if details.get('Constant Value'):
                file.write(f"Constant Value: {details.get('Constant Value')}\n")
            file.write("\n")
    print(f"Permissions have been successfully written to {filename}")


def main():
    print("Fetching Android permissions...")
    html_content = fetch_html(ANDROID_PERMISSION_DOCS_URL)
    if html_content:
        permissions = parse_permission_data(html_content)
        if permissions:
            write_permissions_to_file(permissions, 'android_permissions.txt')
        else:
            print("No permissions were found.")
    else:
        print("Failed to fetch permissions data.")

if __name__ == "__main__":
    main()