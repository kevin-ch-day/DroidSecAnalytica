def analyze_manifest_element(manifest_file_path):
    try:
        with open(manifest_file_path, "r", encoding="utf-8") as manifest_file:
            manifest_content = manifest_file.read()

        manifest_data = {}
        manifest_start = manifest_content.find("<manifest")
        manifest_end = manifest_content.find(">", manifest_start)

        if manifest_start != -1 and manifest_end != -1:
            manifest_attributes = manifest_content[manifest_start:manifest_end]
            manifest_data["package"] = extract_attribute(manifest_attributes, "package")
            manifest_data["compileSdkVersion"] = extract_attribute(manifest_attributes, "android:compileSdkVersion")
            manifest_data["compileSdkVersionCodename"] = extract_attribute(manifest_attributes, "android:compileSdkVersionCodename")
            manifest_data["platformBuildVersionCode"] = extract_attribute(manifest_attributes, "platformBuildVersionCode")
            manifest_data["platformBuildVersionName"] = extract_attribute(manifest_attributes, "platformBuildVersionName")
            manifest_data["targetSdkVersion"] = extract_attribute(manifest_attributes, "android:targetSdkVersion")
            manifest_data["versionCode"] = extract_attribute(manifest_attributes, "android:versionCode")
            manifest_data["versionName"] = extract_attribute(manifest_attributes, "android:versionName")
            manifest_data["installLocation"] = extract_attribute(manifest_attributes, "android:installLocation")
            manifest_data["debuggable"] = extract_attribute(manifest_attributes, "android:debuggable")
            manifest_data["applicationLabel"] = extract_attribute(manifest_attributes, "android:label")
            manifest_data["packageInstaller"] = extract_attribute(manifest_attributes, "android:packageInstaller")

        return manifest_data

    except FileNotFoundError:
        print(f"Error: File not found - {manifest_file_path}")
    
    except Exception as e:
        print(f"Error analyzing AndroidManifest.xml: {e}")
        return None

def extract_attribute(element, attribute_name):
    attribute_start = element.find(attribute_name + "=")

    if attribute_start != -1:
        attribute_start += len(attribute_name) + 2
        attribute_end = element.find("\"", attribute_start)
        if attribute_end != -1:
            return element[attribute_start:attribute_end]

    return ""

def extract_metadata(content, element_name):
    metadata = []
    for line in content:
        if f"<{element_name}" in line:
            metadata_item = {}
            metadata_item["name"] = find_attribute_value(line, 'name')
            metadata.append(metadata_item)
    return metadata

def find_attribute_value(line, attribute_name):
    start_index = line.find(f'{attribute_name}="')
    if start_index == -1:
        return None

    start_index += len(attribute_name) + 2
    end_index = line.find('"', start_index)

    if end_index == -1:
        return None

    return line[start_index:end_index]
