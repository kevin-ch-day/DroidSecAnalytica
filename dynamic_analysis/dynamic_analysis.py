# dynamic_analysis.py

import subprocess

from utils import logging_utils, app_display, user_prompts
from . import device_manager, app_manager, file_system_analysis

# Constants
LOG_FILE = 'logs/dynamic_analysis.log'

# Configure logging
logging_utils.setup_logger(LOG_FILE)

# Dynamic analysis menu
def dynamic_menu():
    while True:
        print(app_display.format_menu_title("Dynamic Analysis Menu"))
        print(app_display.format_menu_option(1, "Run Dynamic Analysis"))
        print(app_display.format_menu_option(2, "Inspect Device"))
        print(app_display.format_menu_option(3, "View Recent Activity"))
        print(app_display.format_menu_option(4, "Capture Screenshots"))
        print(app_display.format_menu_option(5, "Analyze Network Traffic"))
        print(app_display.format_menu_option(6, "Check for Suspicious Permissions"))
        print(app_display.format_menu_option(7, "Analyze File System"))
        print(app_display.format_menu_option(8, "View Installed Apps"))
        print(app_display.format_menu_option(0, "Back to Main Menu"))

        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '2', '3', '4', '5', '6', '7', '8', '0'])

        if menu_choice == '1':
            apk_path = input("Enter the path to the APK: ").strip()
            run_analysis(apk_path)
        elif menu_choice == '2':
            inspect_device()
        elif menu_choice == '3':
            view_recent_activity()
        elif menu_choice == '4':
            capture_screenshots()
        elif menu_choice == '5':
            analyze_network_traffic()
        elif menu_choice == '6':
            check_for_suspicious_permissions()
        elif menu_choice == '7':
            file_system_analysis.analyze_file_system()
        elif menu_choice == '8':
            view_installed_apps()
        elif menu_choice == '0':
            break

# Perform dynamic analysis on an APK file
def run_analysis(apk_path):
    try:
        logging_utils.log_info("Checking connected devices...")
        if not device_manager.check_devices():
            return {
                "Analysis Status": "Failure",
                "Additional Information": "No Android devices or emulators are connected."
            }

        logging_utils.log_info("Starting the emulator...")
        if not device_manager.start_emulator():
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to start the emulator."
            }

        logging_utils.log_info(f"Installing the APK: {apk_path}")
        if not app_manager.install_apk(apk_path):
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to install the APK on the emulator."
            }

        package_name = app_manager.get_package_name(apk_path)

        if not package_name:
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to retrieve the package name of the app."
            }

        logging_utils.log_info(f"Launching the app with package name: {package_name}")
        if not app_manager.launch_app(package_name):
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to launch the app on the emulator."
            }

        # Monitor the app's behavior and collect dynamic analysis
        logging_utils.log_info("Stopping the emulator...")
        if not device_manager.stop_emulator():
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to stop the emulator."
            }

        return {
            "Analysis Status": "Success",
            "Additional Information": "Dynamic analysis completed successfully."
        }

    except Exception as e:
        logging_utils.log_error(f"Dynamic analysis failed with error: {str(e)}")
        return {
            "Analysis Status": "Failure",
            "Additional Information": f"Dynamic analysis failed with error: {str(e)}"
        }

# Inspect a device
def inspect_device():
    try:
        # Implement device inspection logic here
        logging_utils.log_info("Device inspection is not yet implemented.")
    except Exception as e:
        logging_utils.log_error(f"Device inspection failed with error: {str(e)}")

# View recent activity
def view_recent_activity():
    try:
        # Implement recent activity view logic here
        logging_utils.log_info("Viewing recent activity is not yet implemented.")
    except Exception as e:
        logging_utils.log_error(f"Viewing recent activity failed with error: {str(e)}")

# Capture screenshots
def capture_screenshots():
    try:
        # Implement screenshot capture logic here
        logging_utils.log_info("Capturing screenshots is not yet implemented.")
    except Exception as e:
        logging_utils.log_error(f"Screenshot capture failed with error: {str(e)}")

# Analyze network traffic
def analyze_network_traffic():
    try:
        # Implement network traffic analysis logic here
        logging_utils.log_info("Analyzing network traffic is not yet implemented.")
    except Exception as e:
        logging_utils.log_error(f"Network traffic analysis failed with error: {str(e)}")

# Check for suspicious permissions
def check_for_suspicious_permissions():
    try:
        # Implement suspicious permissions check logic here
        logging_utils.log_info("Checking for suspicious permissions is not yet implemented.")
    except Exception as e:
        logging_utils.log_error(f"Suspicious permissions check failed with error: {str(e)}")

def view_installed_apps():
    try:
        # Use adb shell to list the installed packages on the Android device
        logging_utils.log_info("Listing installed apps...")
        result = subprocess.run(["adb", "shell", "pm", "list", "packages", "-f"], capture_output=True, text=True)
        
        if result.returncode == 0:
            app_listing = result.stdout
            logging_utils.log_info(app_listing)
        else:
            logging_utils.log_error("Failed to list installed apps.")
    except Exception as e:
        logging_utils.log_error(f"Viewing installed apps failed with error: {str(e)}")