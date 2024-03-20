def write_andro_data_section(andro_data, file):
    """Writes the Android application data section to the file."""
    file.write("\nAndroid Application Data\n" + "=" * 50 + "\n")
    if andro_data:
        file.write(f"Package Name: {andro_data.get('package', 'N/A')}\n")
        file.write(f"Main Activity: {andro_data.get('main_activity', 'N/A')}\n")
        file.write(f"Target SDK Version: {andro_data.get('target_sdk_version', 'N/A')}\n")
        file.write(f"Minimum SDK Version: {andro_data.get('min_sdk_version', 'N/A')}\n")
        file.write(f"MD5 Hash: {andro_data.get('md5', 'N/A')}\n")
        file.write(f"SHA1 Hash: {andro_data.get('sha1', 'N/A')}\n")
        file.write(f"SHA256 Hash: {andro_data.get('sha256', 'N/A')}\n")
    else:
        file.write("No Android application data available.\n")