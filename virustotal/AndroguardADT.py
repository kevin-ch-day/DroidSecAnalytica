from . import PermissionADT
from . import IntentFilterADT

class AndroguardADT:

    # Initialize AndroguardADT with default values
    def __init__(self, main_activity=None, package=None, target_sdk_version=None):
        self.main_activity = main_activity
        self.package = package
        self.target_sdk_version = target_sdk_version
        self.receivers = []
        self.activities = []
        self.providers = []
        self.services = []
        self.libraries = []
        self.certificate = {}
        self.intent_filters = IntentFilterADT.IntentFilterADT() 
        self.permissions = []  # PermissionADT objects

    # Add a permission object to the permissions list
    def add_permission(self, permission_data):
        if not isinstance(permission_data, PermissionADT.PermissionADT):
            raise TypeError("permission_data must be an instance of PermissionADT")
        self.permissions.append(permission_data)


    # Return the list of permissions
    def get_permissions(self):
        return self.permissions

    # Find a permission by name
    def find_permission(self, p_name):
        if not p_name or not isinstance(p_name, str):
            return None
        p_name = p_name.lower()
        for p in self.permissions:
            if p.get_name().lower() == p_name:
                return p
        return None

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

    # Add a receiver
    def add_receiver(self, receiver):
        self.receivers.append(receiver)

    # Get all receivers
    def get_receivers(self):
        return self.receivers

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

    # Add a library
    def add_library(self, library):
        self.libraries.append(library)

    # Get all libraries
    def get_libraries(self):
        return self.libraries

    # Set the certificate data
    def set_certificate_data(self, certificate_data):
        self.certificate = certificate_data

    # Get the certificate data
    def get_certificate_data(self):
        return self.certificate

    def add_intent_filter(self, entity_type, entity, action, category):
        self.intent_filters.add_intent_filter(entity_type, entity, action, category)

    def get_intent_filter(self, entity_type, entity):
        return self.intent_filters.get_intent_filter(entity_type, entity)

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

    def remove_library(self, library):
        """Remove a library if it exists."""
        try:
            self.libraries.remove(library)
        except ValueError:
            pass  # Optionally handle the error or log it

    def __str__(self):
        """ User-friendly string representation of the AndroguardADT object. """
        info_lines = [
            f"AndroguardADT Object Summary:",
            f"  Main Activity: {self.main_activity or 'Not Set'}",
            f"  Package: {self.package or 'Not Set'}",
            f"  Target SDK Version: {self.target_sdk_version or 'Not Set'}",
            f"  Total Receivers: {len(self.receivers)}",
            f"  Total Activities: {len(self.activities)}",
            f"  Total Providers: {len(self.providers)}",
            f"  Total Services: {len(self.services)}",
            f"  Total Libraries: {len(self.libraries)}",
            f"  Total Permissions: {len(self.permissions)}"
        ]

        # Adding a line about the presence of certificate data
        cert_status = 'Available' if self.certificate else 'Not Available'
        info_lines.append(f"  Certificate Data: {cert_status}")

        # Adding a line about the presence of intent filter data
        intent_filter_status = 'Available' if self.intent_filters else 'Not Available'
        info_lines.append(f"  Intent Filters Data: {intent_filter_status}")

        return "\n".join(info_lines)


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
            f"Number of Libraries: {len(self.libraries)}",
            f"Number of Permissions: {len(self.permissions)}",
        ]

        # Optionally, add more detailed information for each component
        if self.receivers:
            summary_info.append("Receivers: " + ", ".join(self.receivers))
        if self.activities:
            summary_info.append("Activities: " + ", ".join(self.activities))
        # Similar for providers, services, libraries, and permissions

        # Adding certificate summary if present
        if self.certificate:
            summary_info.append(f"Certificate: Available")
        
        # Adding intent filters summary if present
        if self.intent_filters:
            summary_info.append(f"Intent Filters: Available")

        return "\n".join(summary_info)
