from . import AndroPermissionADT
from . import PermissionManager
from . import IntentFilterADT

class AndroguardADT:

    def __init__(self, main_activity=None, package=None, target_sdk_version=None):
        self.md5 = None # MD5 Hash value
        self.sha1 = None # Hash value
        self.sha256 = None # Hash value
        self.main_activity = main_activity
        self.package = package
        self.target_sdk_version = target_sdk_version
        self.min_sdk_version  = None
        self.receivers = []
        self.activities = []
        self.providers = []
        self.services = []
        self.libraries = []
        self.certificate = {}
        self.intent_filters = IntentFilterADT.IntentFilterADT() 
        self.permissions_manager = PermissionManager.PermissionManager()

    def get_md5(self):
        return self.md5

    def set_md5(self, md5):
        self.md5 = md5

    def get_sha1(self):
        return self.sha1

    def set_sha1(self, sha1):
        self.sha1 = sha1

    def get_sha256(self):
        return self.sha256

    def set_sha256(self, sha256):
        self.sha256 = sha256

    def add_permission(self, permission_data):
        if not isinstance(permission_data, AndroPermissionADT.AndroPermissionADT):
            raise TypeError("permission_data must be an instance of AndroPermissionADT")
        self.permissions_manager.add_permission(permission_data)

    def get_permissions(self):
        return self.permissions_manager.get_permissions()

    def get_permission(self, name):
        return self.permissions_manager.get_permission(name)

    def remove_permission(self, name):
        self.permissions_manager.remove_permission(name)

    def search_permissions(self, search_term):
        return self.permissions_manager.search_permissions(search_term)

    # Set the main activity
    def set_main_activity(self, main_activity):
        self.main_activity = main_activity

    # Get the main activity
    def get_main_activity(self):
        return self.main_activity

    # Set the package name
    def set_package(self, package):
        self.package = package

    # Get the package name
    def get_package(self):
        return self.package

    # Set the target SDK version
    def set_target_sdk_version(self, target_sdk_version):
        self.target_sdk_version = target_sdk_version

    # Get the target SDK version
    def get_target_sdk_version(self):
        return self.target_sdk_version

    def set_min_sdk_version(self, set_min_sdk_version):
        self.min_sdk_version = set_min_sdk_version

    def get_min_sdk_version(self):
        return self.min_sdk_version

    # Add a receiver
    def add_receiver(self, receiver):
        self.receivers.append(receiver)

    # Get all receivers
    def get_receivers(self):
        return self.receivers
    
    # Add a library
    def add_library(self, library):
        self.libraries.append(library)

    # Get all libraries
    def add_libraries(self):
        return self.libraries

    # Add an activity
    def add_activity(self, activity):
        self.activities.append(activity)

    # Get all activities
    def get_activities(self):
        return self.activities

    # Add a provider
    def add_provider(self, provider):
        self.providers.append(provider)

    # Get all providers
    def get_providers(self):
        return self.providers

    # Add a service
    def add_service(self, service):
        self.services.append(service)

    # Get all services
    def get_services(self):
        return self.services

    # Set the certificate data
    def set_certificate_data(self, certificate_data):
        self.certificate = certificate_data

    # Get the certificate data
    def get_certificate_data(self):
        return self.certificate

    # Add an intent filter
    def add_intent_filter(self, entity_type, entity, action, category):
        self.intent_filters.add_intent_filter(entity_type, entity, action, category)

    # Get an intent filter for a specific entity
    def get_intent_filter(self, entity_type, entity):
        return self.intent_filters.get_intent_filter(entity_type, entity)

    # Get all intent filters
    def get_all_intent_filters(self):
        return self.intent_filters.get_all_intent_filters()

    def remove_receiver(self, receiver):
        """Remove a receiver if it exists."""
        try:
            self.receivers.remove(receiver)
        except ValueError:
            pass  # Optionally handle the error or log it

    def remove_provider(self, provider):
        """Remove a provider if it exists."""
        try:
            self.providers.remove(provider)
        except ValueError:
            pass  # Optionally handle the error or log it

    def remove_service(self, service):
        """Remove a service if it exists."""
        try:
            self.services.remove(service)
        except ValueError:
            pass  # Optionally handle the error or log it
    
    def __str__(self) -> str:
        """Provides an enhanced, detailed string representation of the APK file, with hashes first and comprehensive analysis."""
        
        # Header for the analysis report
        header = (
            "================ APK Object ================\n"
            f"APK Name: {self.package or 'N/A'}\n"
            "=====================================================\n"
        )

        # Hashes information
        hashes_summary = {
            "MD5 Hash": self.md5 or "N/A",
            "SHA1 Hash": self.sha1 or "N/A",
            "SHA256 Hash": self.sha256 or "N/A"
        }

        # Basic APK metadata
        apk_summary = {
            "Main Activity": self.main_activity or "N/A",
            "Package": self.package or "N/A",
            "Version Code": getattr(self, 'version_code', "N/A"),  # If version_code exists
            "Version Name": getattr(self, 'version_name', "N/A"),  # If version_name exists
            "Target SDK Version": self.target_sdk_version or "N/A",
            "Min SDK Version": getattr(self, 'min_sdk_version', "N/A"),  # If min_sdk_version exists
            "Compile SDK Version": getattr(self, 'compile_sdk_version', "N/A"),  # If compile_sdk_version exists
            "Number of Receivers": len(self.receivers),
            "Number of Activities": len(self.activities),
            "Number of Providers": len(self.providers),
            "Number of Services": len(self.services),
            "Number of Permissions": len(self.permissions_manager.get_permissions())
        }

        # Create detailed sections for each component
        def format_list(items, item_type):
            """Helper function to format lists for components like activities, receivers, etc."""
            if items:
                return f"\n{item_type}:\n" + "\n".join([f"  - {item}" for item in items])
            return f"\n{item_type}:\n  None"

        # Formatting each section (if items exist, they will be listed, otherwise "None" is shown)
        receivers_detail = format_list(self.receivers, "\nReceivers")
        activities_detail = format_list(self.activities, "\nActivities")
        providers_detail = format_list(self.providers, "\nProviders")
        services_detail = format_list(self.services, "\nServices")
        permissions_detail = format_list(self.permissions_manager.get_permissions(), "\nPermissions")

        # Hashes and APK summary as text
        hashes_parts = [f"{key}: {value}" for key, value in hashes_summary.items()]
        summary_parts = [f"{key}: {value}" for key, value in apk_summary.items()]
        
        # Footer
        footer = "\n================ End  ================\n"

        # Joining all sections
        return (
            header
            + "\n--- APK Hashes ---\n" + "\n".join(hashes_parts)
            + "\n\n--- APK Metadata ---\n" + "\n".join(summary_parts)
            + receivers_detail
            + activities_detail
            + providers_detail
            + services_detail
            + permissions_detail
            + footer
        )


    def remove_activity(self, activity):
        """ Remove an activity if it exists """
        try:
            self.activities.remove(activity)
        except ValueError:
            pass 

    def update_permission(self, p_name, new_data):
        """ Update a permission if it exists """
        permission = self.find_permission(p_name)
        if permission:
            if 'name' in new_data:
                permission.set_name(new_data['name'])
            if 'short_desc' in new_data:
                permission.set_short_desc(new_data['short_desc'])
            if 'long_desc' in new_data:
                permission.set_long_desc(new_data['long_desc'])
            if 'permission_type' in new_data:
                permission.set_permission_type(new_data['permission_type'])

    def summary(self):
        """ Returns a detailed summary of the AndroguardADT object. """
        summary_info = [
            f"Main Activity: {self.main_activity}",
            f"Package: {self.package}",
            f"Target SDK Version: {self.target_sdk_version}",
            f"Number of Receivers: {len(self.receivers)}",
            f"Number of Activities: {len(self.activities)}",
            f"Number of Providers: {len(self.providers)}",
            f"Number of Services: {len(self.services)}",
            f"Number of Permissions: {len(self.permissions)}",
        ]

        return "\n".join(summary_info)
