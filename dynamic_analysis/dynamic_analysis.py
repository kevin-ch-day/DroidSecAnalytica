import subprocess
import tempfile
import logging

from utils import app_display, app_utils

# Constants
LOG_FILE = 'logs/dynamic_analysis.log'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def dynamic_analysis_menu():
    print(app_display.format_menu_title("Dynamic Analysis Menu"))
    print(app_display.format_menu_option(1, "Run Dynamic Analysis"))
    print(app_display.format_menu_option(0, "Back to Main Menu"))

def handle_dynamic_analysis():
    dynamic_analysis_menu()
    da_choice = app_utils.get_user_choice("\nEnter your choice: ", ['1', '0'])
    if da_choice == '1':
        apk_path = input("Enter the path to the APK: ").strip()
        run_dynamic_analysis(apk_path)

def check_devices():
    """
    Check if any Android devices or emulators are connected.

    Returns:
        bool: True if devices are connected, False otherwise.
    """
    try:
        # Use the 'adb devices' command to list connected devices
        adb_command = "adb devices"
        output = subprocess.check_output(adb_command, shell=True, universal_newlines=True)

        # Check if any devices/emulators are listed
        if "List of devices attached" in output:
            lines = output.split('\n')
            connected_devices = [line.strip() for line in lines[1:] if line.strip()]
            return len(connected_devices) > 0
        else:
            return False

    except Exception as e:
        logging.error(f"Error checking connected devices: {str(e)}")
        return False

def start_emulator():
    """
    Start the Android Emulator.

    Returns:
        bool: True if emulator started successfully, False otherwise.
    """
    try:
        emulator_dir = tempfile.mkdtemp()
        emulator_command = f"emulator -avd <YOUR_AVD_NAME>"
        subprocess.run(emulator_command, shell=True, cwd=emulator_dir)
        return True

    except Exception as e:
        logging.error(f"Error starting emulator: {str(e)}")
        return False

def install_apk(apk_path):
    """
    Install an APK file on the emulator.

    Args:
        apk_path (str): The path to the APK file.

    Returns:
        bool: True if installation successful, False otherwise.
    """
    try:
        install_command = f"adb install {apk_path}"
        subprocess.run(install_command, shell=True)
        return True

    except Exception as e:
        logging.error(f"Error installing APK: {str(e)}")
        return False

def launch_app(package_name):
    """
    Launch an app on the emulator.

    Args:
        package_name (str): The package name of the app.

    Returns:
        bool: True if app launched successfully, False otherwise.
    """
    try:
        launch_command = f"adb shell monkey -p {package_name} 1"
        subprocess.run(launch_command, shell=True)
        return True

    except Exception as e:
        logging.error(f"Error launching app: {str(e)}")
        return False

def stop_emulator():
    """
    Stop the Android Emulator.

    Returns:
        bool: True if emulator stopped successfully, False otherwise.
    """
    try:
        stop_command = "adb emu kill"
        subprocess.run(stop_command, shell=True)
        return True

    except Exception as e:
        logging.error(f"Error stopping emulator: {str(e)}")
        return False

def run_dynamic_analysis(apk_path):
    """
    Perform dynamic analysis on an APK file.

    Args:
        apk_path (str): The path to the APK file.

    Returns:
        dict: A dictionary containing the dynamic analysis results.
    """
    try:
        print("Checking connected devices...")
        if not check_devices():
            return {
                "Analysis Status": "Failure",
                "Additional Information": "No Android devices or emulators are connected."
            }

        print("Starting the emulator...")
        if not start_emulator():
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to start the emulator."
            }

        print(f"Installing the APK: {apk_path}")
        if not install_apk(apk_path):
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to install the APK on the emulator."
            }

        package_name = get_package_name(apk_path)

        if not package_name:
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to retrieve the package name of the app."
            }

        print(f"Launching the app with package name: {package_name}")
        if not launch_app(package_name):
            return {
                "Analysis Status": "Failure",
                "Additional Information": "Failed to launch the app on the emulator."
            }

        # Monitor the app's behavior and collect dynamic analysis data here
        # ...

        print("Stopping the emulator...")
        if not stop_emulator():
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

def get_package_name(apk_path):
    """
    Get the package name of an APK file.

    Args:
        apk_path (str): The path to the APK file.

    Returns:
        str: The package name, or an empty string if not found.
    """
    try:
        aapt_command = f"aapt dump badging {apk_path} | grep package | awk '{{print $2}}' | sed s/name=//g | sed s/\\'/\\\"/g"
        output = subprocess.check_output(aapt_command, shell=True, universal_newlines=True)
        return output.strip()

    except Exception as e:
        logging.error(f"Error getting package name: {str(e)}")
        return ""

if __name__ == "__main__":
    print("Dynamic Analysis Script")
    apk_path = input("Enter the path to the APK file: ")
    analysis_result = perform_dynamic_analysis(apk_path)
    print("\nAnalysis Result:")
    print(f"Status: {analysis_result['Analysis Status']}")
    print(f"Additional Information: {analysis_result['Additional Information']}")
