# AndroPermissionADT.py

class AndroPermissionADT:
    _instances = {}

    def __init__(self, name: str = "", short_desc: str = "", long_desc: str = "", permission_type: str = ""):
        self._name = name
        self._short_desc = short_desc
        self._long_desc = long_desc
        self._permission_type = permission_type
        AndroPermissionADT._instances[name] = self

    @classmethod
    def get_instance(cls, name):
        return cls._instances.get(name)

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
        # Sets a new short description for the permission, removing newline characters
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

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "short_desc": self.short_desc,
            "long_desc": self.long_desc,
            "perm_type": self.permission_type
        }

    def __str__(self) -> str:
        return f"PermissionADT(Name: {self.name}, Type: {self.permission_type}, Desc: {self.short_desc})"

    def __repr__(self) -> str:
        return f"PermissionADT(name='{self.name}', short_desc='{self.short_desc}', long_desc='{self.long_desc}', permission_type='{self.permission_type}')"

    def __eq__(self, other) -> bool:
        return isinstance(other, AndroPermissionADT) and self.to_dict() == other.to_dict()
    
    def __iter__(self):
        for attr_name in ["name", "short_desc", "long_desc", "permission_type"]:
            yield getattr(self, attr_name)

    def __repr__(self):
        return f"PermissionADT(name='{self._name}', short_desc='{self._short_desc}', long_desc='{self._long_desc}', permission_type='{self._permission_type}')"

    def display_summary(self):
        return f"Name: {self._name} Description: {self._short_desc} Type: {self._permission_type}"
