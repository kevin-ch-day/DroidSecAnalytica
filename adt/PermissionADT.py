# PermissionADT.py

class PermissionADT:
    def __init__(self, name: str = "", short_desc: str = "", long_desc: str = "", permission_type: str = ""):
        # Initialize a new PermissionADT instance
        self._name = name
        self._short_desc = short_desc
        self._long_desc = long_desc
        self._permission_type = permission_type

    @property
    def name(self) -> str:
        # Returns the name of the permission
        return self._name

    @name.setter
    def name(self, value: str):
        # Sets a new name for the permission
        if not isinstance(value, str):
            raise ValueError("Name must be a string")
        self._name = value

    @property
    def short_desc(self) -> str:
        # Returns the short description of the permission
        return self._short_desc

    @short_desc.setter
    def short_desc(self, value: str):
        # Sets a new short description for the permission
        if not isinstance(value, str):
            raise ValueError("Short description must be a string")
        self._short_desc = value

    @property
    def long_desc(self) -> str:
        # Returns the long description of the permission
        return self._long_desc

    @long_desc.setter
    def long_desc(self, value: str):
        # Sets a new long description for the permission
        if not isinstance(value, str):
            raise ValueError("Long description must be a string")
        self._long_desc = value

    @property
    def permission_type(self) -> str:
        # Returns the type of the permission
        return self._permission_type

    @permission_type.setter
    def permission_type(self, value: str):
        # Sets a new type for the permission
        if not isinstance(value, str):
            raise ValueError("Permission type must be a string")
        self._permission_type = value

    def __str__(self) -> str:
        # String representation of the PermissionADT object
        return f"PermissionADT(Name: {self._name}, Type: {self._permission_type})"

    def __eq__(self, other) -> bool:
        # Equality comparison for PermissionADT objects
        return isinstance(other, PermissionADT) and self.__dict__ == other.__dict__
