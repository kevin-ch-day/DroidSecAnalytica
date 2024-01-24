# app_manager.py

import subprocess
from utils import logging_utils

def install_apk(apk_path):
    try:
        install_command = ["adb", "install", apk_path]
        subprocess.run(install_command, check=True)
        logging_utils.log_info(f"APK installed successfully: {apk_path}")
        return True
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error installing APK {apk_path}: {e.output}")
        return False
    except Exception as e:
        logging_utils.log_error(f"Unexpected error installing APK {apk_path}: {e}")
        return False

def uninstall_apk(package_name):
    try:
        uninstall_command = ["adb", "uninstall", package_name]
        subprocess.run(uninstall_command, check=True)
        logging_utils.log_info(f"APK uninstalled successfully: {package_name}")
        return True
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error uninstalling APK {package_name}: {e.output}")
        return False
    except Exception as e:
        logging_utils.log_error(f"Unexpected error uninstalling APK {package_name}: {e}")
        return False

def launch_app(package_name):
    try:
        launch_command = ["adb", "shell", "monkey", "-p", package_name, "1"]
        subprocess.run(launch_command, check=True)
        logging_utils.log_info(f"App launched successfully: {package_name}")
        return True
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error launching app {package_name}: {e.output}")
        return False
    except Exception as e:
        logging_utils.log_error(f"Unexpected error launching app {package_name}: {e}")
        return False

def check_app_installed(package_name):
    try:
        check_command = ["adb", "shell", "pm", "list", "packages", package_name]
        result = subprocess.run(check_command, check=True, capture_output=True, text=True)
        is_installed = package_name in result.stdout
        return is_installed
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error checking if app is installed {package_name}: {e.output}")
        return False

def get_installed_apps():
    try:
        command = ["adb", "shell", "pm", "list", "packages"]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        installed_apps = result.stdout.splitlines()
        logging_utils.log_info("Retrieved list of installed apps.")
        return installed_apps
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error retrieving installed apps: {e.output}")
        return []
    except Exception as e:
        logging_utils.log_error(f"Unexpected error retrieving installed apps: {e}")
        return []

def clear_app_data(package_name):
    try:
        command = ["adb", "shell", "pm", "clear", package_name]
        subprocess.run(command, check=True)
        logging_utils.log_info(f"App data cleared for: {package_name}")
        return True
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error clearing app data for {package_name}: {e.output}")
        return False
    except Exception as e:
        logging_utils.log_error(f"Unexpected error clearing app data for {package_name}: {e}")
        return False
