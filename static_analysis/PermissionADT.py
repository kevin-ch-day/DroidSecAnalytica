class PermissionADT:
    def __init__(self, name="", short_desc="", long_desc="", permission_type=""):
        """
        Initialize a new PermissionADT instance.
        
        :param name: Name of the permission.
        :param short_desc: Short description of the permission.
        :param long_desc: Long description of the permission.
        :param permission_type: Type of the permission.
        """
        self.name = name
        self.short_desc = short_desc
        self.long_desc = long_desc
        self.permission_type = permission_type

    def get_name(self):
        """Returns the name of the permission."""
        return self.name

    def set_name(self, name):
        """Sets a new name for the permission."""
        if isinstance(name, str):
            self.name = name
        else:
            raise ValueError("Name must be a string")

    def get_short_desc(self):
        """Returns the short description of the permission."""
        return self.short_desc

    def set_short_desc(self, short_desc):
        """Sets a new short description for the permission."""
        if isinstance(short_desc, str):
            self.short_desc = short_desc
        else:
            raise ValueError("Short description must be a string")

    def get_long_desc(self):
        """Returns the long description of the permission."""
        return self.long_desc

    def set_long_desc(self, long_desc):
        """Sets a new long description for the permission."""
        if isinstance(long_desc, str):
            self.long_desc = long_desc
        else:
            raise ValueError("Long description must be a string")

    def get_permission_type(self):
        """Returns the type of the permission."""
        return self.permission_type

    def set_permission_type(self, permission_type):
        """Sets a new type for the permission."""
        if isinstance(permission_type, str):
            self.permission_type = permission_type
        else:
            raise ValueError("Permission type must be a string")

    def __str__(self):
        """String representation of the PermissionADT object."""
        return f"PermissionADT(Name: {self.name}, Type: {self.permission_type})"

    def __eq__(self, other):
        """Equality comparison for PermissionADT objects."""
        if isinstance(other, PermissionADT):
            return (self.name == other.name and
                    self.short_desc == other.short_desc and
                    self.long_desc == other.long_desc and
                    self.permission_type == other.permission_type)
        return False