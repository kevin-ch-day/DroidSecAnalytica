# static_analysis/static_analysis.py
import os
import subprocess
import logging

# Constants
LOG_FILE = 'logs/static_analysis.log'
ANALYSIS_OUTPUT_DIR = 'analysis_results'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_output_directory():
    """Create the output directory if it doesn't exist."""
    os.makedirs(ANALYSIS_OUTPUT_DIR, exist_ok=True)

def decompile_apk(apk_path):
    """
    Decompile an APK file and save the decompiled code.

    Args:
        apk_path (str): The path to the APK file.
    """
    try:
        output_directory = os.path.join(ANALYSIS_OUTPUT_DIR, os.path.splitext(os.path.basename(apk_path))[0])
        create_output_directory()
        subprocess.run(["apktool", "d", apk_path, "-o", output_directory], check=True)
        logging.info(f"APK decompiled successfully. Output directory: {output_directory}")
        return output_directory

    except subprocess.CalledProcessError as e:
        logging.error(f"Error decompiling APK: {e}")
        return None

def analyze_android_manifest(decompiled_dir):
    """
    Analyze the AndroidManifest.xml file in the decompiled directory.

    Args:
        decompiled_dir (str): The directory containing the decompiled APK.

    Returns:
        dict: A dictionary containing metadata from the manifest file.
    """
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    manifest_data = {}
    
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_content = f.read()

        # Extract relevant data from the manifest (customize as needed)
        package_name = extract_manifest_attribute(manifest_content, "package")
        permissions = extract_permissions(manifest_content)
        activities = extract_manifest_components(manifest_content, "activity")
        services = extract_manifest_components(manifest_content, "service")
        providers = extract_manifest_components(manifest_content, "provider")

        manifest_data["package_name"] = package_name
        manifest_data["permissions"] = permissions
        manifest_data["activities"] = activities
        manifest_data["services"] = services
        manifest_data["providers"] = providers

        logging.info("AndroidManifest.xml analysis completed.")
        return manifest_data

    except FileNotFoundError:
        logging.error(f"Error: AndroidManifest.xml not found at {manifest_path}")
    except Exception as e:
        logging.error(f"Error analyzing AndroidManifest.xml: {e}")
    
    return None

def extract_manifest_attribute(manifest_content, attribute_name):
    """
    Extract a specific attribute value from the AndroidManifest.xml content.

    Args:
        manifest_content (str): The content of the AndroidManifest.xml file.
        attribute_name (str): The name of the attribute to extract.

    Returns:
        str: The extracted attribute value, or None if not found.
    """
    try:
        start = manifest_content.find(f'{attribute_name}="')
        if start != -1:
            start += len(attribute_name) + 2  # Account for the attribute name and the equal sign
            end = manifest_content.find('"', start)
            return manifest_content[start:end]
    except Exception as e:
        logging.error(f"Error extracting {attribute_name}: {e}")
    
    return None

def extract_permissions(manifest_content):
    """
    Extract permissions from the AndroidManifest.xml content.

    Args:
        manifest_content (str): The content of the AndroidManifest.xml file.

    Returns:
        list: A list of extracted permissions.
    """
    permissions = []
    try:
        permission_start = manifest_content.find("<uses-permission")
        while permission_start != -1:
            permission_end = manifest_content.find("/>", permission_start)
            permission_line = manifest_content[permission_start:permission_end + 2]
            permission = extract_manifest_attribute(permission_line, "android:name")
            if permission:
                permissions.append(permission)
            permission_start = manifest_content.find("<uses-permission", permission_end)
    except Exception as e:
        logging.error(f"Error extracting permissions: {e}")
    
    return permissions

def extract_manifest_components(manifest_content, component_type):
    """
    Extract components (e.g., activities, services) from the AndroidManifest.xml content.

    Args:
        manifest_content (str): The content of the AndroidManifest.xml file.
        component_type (str): The type of component to extract (e.g., 'activity', 'service').

    Returns:
        list: A list of extracted components.
    """
    components = []
    try:
        start = manifest_content.find(f"<{component_type}")
        while start != -1:
            end = manifest_content.find("</{component_type}>", start)
            component_line = manifest_content[start:end + len(component_type) + 3]
            component_name = extract_manifest_attribute(component_line, "android:name")
            if component_name:
                components.append(component_name)
            start = manifest_content.find(f"<{component_type}", end)
    except Exception as e:
        logging.error(f"Error extracting {component_type}s: {e}")
    
    return components

def execute_static_analysis(apk_path):
    """
    Main function for static analysis of an APK file.

    Args:
        apk_path (str): The path to the APK file.
    """
    print(f"Performing static analysis on {apk_path}...\n")
    
    try:
        decompiled_dir = decompile_apk(apk_path)
        if decompiled_dir:
            manifest_data = analyze_android_manifest(decompiled_dir)
            
            # Add more static analysis steps as needed
            
            if manifest_data:
                # Print or save the analyzed data
                print("Static analysis completed.")
                save_results(apk_path, manifest_data)

    except Exception as e:
        print(f"Error during static analysis: {str(e)}")

def save_results(apk_path, manifest_data):
    """
    Save the static analysis results to a file.

    Args:
        apk_path (str): The path to the APK file.
        manifest_data (dict): The analyzed data from the AndroidManifest.xml file.
    """
    try:
        create_output_directory()
        output_file = os.path.join(ANALYSIS_OUTPUT_DIR, f"{os.path.splitext(os.path.basename(apk_path))[0]}_analysis_results.txt")
        
        with open(output_file, "w") as f:
            f.write("Static Analysis Results:\n")
            f.write(f"APK Name: {os.path.basename(apk_path)}\n")
            f.write(f"Package Name: {manifest_data.get('package_name', 'N/A')}\n")
            
            # Permissions
            permissions = manifest_data.get('permissions', ['N/A'])
            if permissions:
                f.write("\nPermissions:\n")
                for index, permission in enumerate(permissions, start=1):
                    f.write(f"[{index}] {permission}\n")
            
            # Activities
            activities = manifest_data.get('activities', ['N/A'])
            if activities:
                f.write(f"\nActivities: {', '.join(activities)}\n")
            
            # Services
            services = manifest_data.get('services', ['N/A'])
            if services:
                f.write(f"Services: {', '.join(services)}\n")
            
            # Providers
            providers = manifest_data.get('providers', ['N/A'])
            if providers:
                f.write(f"Providers: {', '.join(providers)}\n")
        
        logging.info(f"Static analysis results saved to {output_file}")

    except Exception as e:
        logging.error(f"Error saving analysis results: {e}")
