# permission_catorgies_data.py

permissions_data = [
    'ACCESS_COARSE_LOCATION', 'ACCESS_FINE_LOCATION', 'ACCESS_WIFI_STATE',
    'ACTION_MANAGE_OVERLAY_PERMISSION', 'BIND_DEVICE_ADMIN', 'BLUETOOTH',
    'BLUETOOTH_ADMIN', 'CALL_PHONE', 'CAMERA', 'CHANGE_WIFI_STATE', 'GET_TASKS',
    'INTERNET', 'PACKAGE_USAGE_STATS', 'READ_CALENDAR', 'READ_CONTACTS',
    'READ_EXTERNAL_STORAGE', 'READ_PHONE_STATE', 'READ_SMS', 'RECEIVE_SMS',
    'RECORD_AUDIO', 'REQUEST_INSTALL_PACKAGES', 'SEND_SMS', 'SYSTEM_ALERT_WINDOW',
    'USE_BIOMETRIC', 'USE_FINGERPRINT', 'WRITE_CALENDAR', 'WRITE_CONTACTS', 'WRITE_EXTERNAL_STORAGE'
]

overlay_permissions = [
    'SYSTEM_ALERT_WINDOW', 'INTERNET', 'ACCESS_NETWORK_STATE',
    'READ_PHONE_STATE', 'READ_SMS', 'RECEIVE_SMS', 'READ_CONTACTS', 'WRITE_EXTERNAL_STORAGE'
]

sms_permissions = [
    'RECEIVE_SMS', 'RECEIVE_MMS', 'READ_SMS', 'SEND_SMS', 'WRITE_SMS'
]

processes_permissions = [
    'BROADCAST_STICKY', 'FOREGROUND_SERVICE', 'KILL_BACKGROUND_PROCESSES',
    'REQUEST_COMPANION_RUN_IN_BACKGROUND',
    'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS'
]

phone_permissions = [
    'CALL_PHONE', 'MANAGE_OWN_CALLS', 'MODIFY_PHONE_STATE', 'PHONE',
    'PROCESS_OUTGOING_CALLS', 'READ_PHONE_NUMBERS', 'READ_PHONE_STATE', 'READ_PRIVILEGED_PHONE_STATE'
]

storage_permissions = [
    'ACCESS_ALL_EXTERNAL_STORAGE', 'ACCESS_MTP', 'MANAGE_EXTERNAL_STORAGE',
    'MOUNT_UNMOUNT_FILESYSTEMS', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'
]

network_permissions = [
    'ACCESS_NETWORK_STATE', 'ACCESS_WIFI_STATE', 'CHANGE_NETWORK_STATE',
    'CHANGE_WIFI_MULTICAST_STATE', 'CHANGE_WIFI_STATE', 'INTERNET', 'NFC',
    'REQUEST_COMPANION_USE_DATA_IN_BACKGROUND', 'com.google.android.c2dm.permission.RECEIVE'
]

system_file_permissions = [
    'SYSTEM_ALERT_WINDOW', 'WRITE_EXTERNAL_STORAGE',
    'MOUNT_UNMOUNT_FILESYSTEMS', 'MODIFY_AUDIO_SETTINGS', 'BIND_DEVICE_ADMIN',
    'BIND_ACCESSIBILITY_SERVICE', 'WRITE_SYNC_SETTINGS'
]

accessibility_permissions = [
    'BIND_ACCESSIBILITY_SERVICE'
]

package_permissions = [
    'CLEAR_APP_CACHE', 'DELETE_CACHE_FILES', 'INSTALL_PACKAGES', 
    'PACKAGE_USAGE_STATS', 'QUERY_ALL_PACKAGES', 'REQUEST_DELETE_PACKAGES',
    'REQUEST_INSTALL_PACKAGES'
]

camera_permissions = [
    'CAMERA'
]

video_permissions = [
    'CAPTURE_VIDEO_OUTPUT', 'CAPTURE_SECURE_VIDEO_OUTPUT'
]

user_interface_permissions = [
    'EXPAND_STATUS_BAR', 'SET_WALLPAPER', 'SET_WALLPAPER_HINTS', 
    'UNINSTALL_SHORTCUT', 'USE_FULL_SCREEN_INTENT'
]

location_permissions = [
    'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION'
]

booting_permissions = [
    'RECEIVE_BOOT_COMPLETED'
]

contact_permissions = [
    'WRITE_CONTACTS', 'READ_CONTACTS'
]