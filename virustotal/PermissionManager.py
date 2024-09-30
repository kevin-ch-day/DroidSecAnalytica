from . import AndroPermissionADT
import bisect

class PermissionManager:
    def __init__(self, initial_permissions=None):
        self._permissions = {}
        if initial_permissions:
            for permission in initial_permissions:
                self.add_permission(permission)

    def add_permission(self, permission: AndroPermissionADT.AndroPermissionADT):
        self._permissions[permission.name] = permission
    
    def find_insert_position(self, permission_name: str) -> int:
        return bisect.bisect_left([perm.name for perm in self._permissions], permission_name)

    def get_permission(self, name: str) -> AndroPermissionADT.AndroPermissionADT:
        return self._permissions.get(name)

    def remove_permission(self, name: str):
        if name in self._permissions:
            del self._permissions[name]

    def permission_exists(self, name: str) -> bool:
        return name in self._permissions
    
    def list_permissions(self):
        for i in self._permissions:
            print(i)

    def get_permissions(self) -> AndroPermissionADT.AndroPermissionADT:
        return self._permissions
