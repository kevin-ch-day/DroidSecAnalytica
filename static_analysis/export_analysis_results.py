import logging

# Save the static scan results
def save_static_results(apk_basename, manifest_data, manifest_element):
    file_path = 'output/static_analysis_results.txt'
    try:
        with open(file_path, "w") as f:
            f.write(f"Static Analysis Results\n")
            f.write(f"APK: {apk_basename}\n")
            f.write("=" * 60 + "\n\n")

            write_manifest_data(f, manifest_data)
            write_manifest_element_data(f, manifest_element)

        logging.info(f"Static analysis results saved to {file_path}")

    except Exception as e:
        logging.error(f"Error saving analysis results: {e}")

def write_manifest_data(file, manifest_data):
    file.write("Manifest Data:\n")
    file.write("-" * 60 + "\n")
    for element, metadata_list in manifest_data.items():
        file.write(f"  {element.capitalize()}:\n")
        for index, metadata_item in enumerate(metadata_list, start=1):
            file.write(f"    [{index}] Name: {metadata_item['name']}\n")
        file.write("\n")

def write_manifest_element_data(file, manifest_element):
    file.write("Manifest Element Data:\n")
    file.write("-" * 60 + "\n")
    for attribute, value in manifest_element.items():
        if value:
            description = get_attribute_description(attribute)
            file.write(f"  {attribute}:\n")
            file.write(f"    Value: {value}\n")
            file.write(f"    Description: {description}\n\n")

def get_attribute_description(attribute):
    attribute_description = {
        "package": "The name of the package",
        "compileSdkVersion": "The compile SDK version",
        "compileSdkVersionCodename": "The compile SDK version codename",
        "platformBuildVersionCode": "The platform build version code",
        "platformBuildVersionName": "The platform build version name",
        "targetSdkVersion": "The target SDK version",
        "versionCode": "The version code",
        "versionName": "The version name",
        "installLocation": "The install location",
        "debuggable": "Whether the app is debuggable",
        "applicationLabel": "The application label",
        "packageInstaller": "The package installer",
    }
    return attribute_description.get(attribute, "No description available")