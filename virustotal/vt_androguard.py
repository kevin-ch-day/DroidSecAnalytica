from . import AndroguardADT, AndroPermissionADT

def handle_androguard_response(api_response):
    # Main entry point for handling the VirusTotal androguard response.
    # Processes APK information and extracts important metadata for analysis.
    try:

        # Safely get data from the response
        response_data = api_response.get('data', {})
        if not response_data:
            print("[Error] Missing 'data' in API response.")
            return None

        # Get attributes, androguard data
        data_attributes = response_data.get('attributes', {})
        androguard_data = data_attributes.get('androguard', None)
        if not androguard_data:
            print("[Error] Missing 'androguard' in attributes.")
            return None

        # Initialize the AndroguardADT object
        androguard = AndroguardADT.AndroguardADT()

        # Set hashes (MD5, SHA1, SHA256)
        _populate_hashes(androguard, data_attributes)

        # Populate APK metadata (main activity, package name, SDK versions)
        _populate_manifest_metadata(androguard, androguard_data)

        # Populate components (activities, services, receivers, etc.)
        _populate_manifest_components(androguard, androguard_data)

        # Populate permissions with detailed descriptions
        _populate_permissions(androguard, androguard_data)

        return androguard

    except Exception as e:
        print(f"[Error] Error in handle_androguard_response(): {str(e)}")
        return None

def _populate_hashes(androguard, data):
    # Populates hash values (MD5, SHA1, SHA256) in the AndroguardADT object.
    try:
        md5 = data.get('md5', 'N/A')
        sha1 = data.get('sha1', 'N/A')
        sha256 = data.get('sha256', 'N/A')

        androguard.set_md5(md5)
        androguard.set_sha1(sha1)
        androguard.set_sha256(sha256)

    except Exception as e:
        print(f"[Error] Error in _populate_hashes(): {str(e)}")

def _populate_manifest_metadata(androguard, data):
    # Populates APK metadata such as main activity, package name, SDK versions.
    try:
        # Extract metadata safely
        main_activity = data.get('main_activity', 'N/A')
        package_name = data.get('Package', 'N/A')
        target_sdk_version = data.get('TargetSdkVersion', 'N/A')
        min_sdk_version = data.get('MinSdkVersion', 'N/A')

        # Set metadata in AndroguardADT object
        androguard.set_main_activity(main_activity)
        androguard.set_package(package_name)
        androguard.set_target_sdk_version(target_sdk_version)
        androguard.set_min_sdk_version(min_sdk_version)

    except KeyError as e:
        print(f"[Error] KeyError in _populate_manifest_metadata(): {str(e)}")
    except Exception as e:
        print(f"[Error] Unhandled error in _populate_manifest_metadata(): {str(e)}")

def _populate_manifest_components(androguard, data):
    # Populates APK components such as activities, services, receivers, and providers.
    try:

        # Handle activities
        activities = data.get('Activities', [])
        for activity in activities:
            androguard.add_activity(activity)
        #print(f"Added {len(activities)} activities.") # DEBUGFGING

        # Handle receivers
        receivers = data.get('Receivers', [])
        for receiver in receivers:
            androguard.add_receiver(receiver)
        #print(f"Added {len(receivers)} receivers.") # DEBUGFGING

        # Handle providers
        providers = data.get('Providers', [])
        for provider in providers:
            androguard.add_provider(provider)
        #print(f"Added {len(providers)} providers.") # DEBUGFGING

        # Handle services
        services = data.get('Services', [])
        for service in services:
            androguard.add_service(service)
        #print(f"Added {len(services)} services.") # DEBUGFGING

    except KeyError as e:
        print(f"[Error] KeyError in _populate_manifest_components(): {str(e)}")
    except Exception as e:
        print(f"[Error] Unhandled error in _populate_manifest_components(): {str(e)}")

def _populate_permissions(androguard, data):
    # Populates APK permissions, including permission details like descriptions and types.
    try:

        permission_details = data.get('permission_details', {})
        for permission, details in permission_details.items():
            short_description = details.get('short_description', 'N/A')
            full_description = details.get('full_description', 'N/A')
            permission_type = details.get('permission_type', 'N/A')

            # Create AndroPermissionADT object for each permission
            perm_obj = AndroPermissionADT.AndroPermissionADT(
                permission, short_description, full_description, permission_type
            )

            # Add permission object to AndroguardADT
            androguard.add_permission(perm_obj)

        #print(f"Added {len(permission_details)} permissions.") #DEBUGGING

    except KeyError as e:
        print(f"[Error] KeyError in _populate_permissions(): {str(e)}")
    except Exception as e:
        print(f"[Error] Unhandled error in _populate_permissions(): {str(e)}")
