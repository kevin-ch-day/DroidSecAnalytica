import logging

from . import device_manager, app_manager
from utils import app_display, user_prompts

# Constants
LOG_FILE = 'logs/dynamic_analysis.log'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main_menu():
    print(app_display.format_menu_title("Dynamic Analysis Menu"))
    print(app_display.format_menu_option(1, "Run Dynamic Analysis"))
    print(app_display.format_menu_option(0, "Back to Main Menu"))
    menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '0'])
    if menu_choice == '1':
        apk_path = input("Enter the path to the APK: ").strip()
        run_analysis(apk_path)

# Perform dynamic analysis on an APK file
def run_analysis(apk_path):
    try:
        print("Checking connected devices...")
        if not device_manager.check_devices():
            return {
                "Analysis Status": "Failure",
                "Additional Information": "No Android devices or emulators are connected."
            }

        print("Starting the emulator...")
        if not device_manager.start_emulator():
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to start the emulator."
            }

        print(f"Installing the APK: {apk_path}")
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

        print(f"Launching the app with package name: {package_name}")
        if not app_manager.launch_app(package_name):
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to launch the app on the emulator."
            }

        # Monitor the app's behavior and collect dynamic analysis
        print("Stopping the emulator...")
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
        logging.error(f"Dynamic analysis failed with error: {str(e)}")
        return {
            "Analysis Status": "Failure",
            "Additional Information": f"Dynamic analysis failed with error: {str(e)}"
        }
