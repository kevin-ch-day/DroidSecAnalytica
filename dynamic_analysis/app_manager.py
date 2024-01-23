
import subprocess
import logging

# Constants
LOG_FILE = 'logs/app_manager.log'

# Configure logging for app management
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def install_apk(apk_path):
    try:
        install_command = f"adb install {apk_path}"
        subprocess.run(install_command, shell=True)
        return True
    except Exception as e:
        logging.error(f"Error installing APK: {str(e)}")
        return False

def launch_app(package_name):
    try:
        launch_command = f"adb shell monkey -p {package_name} 1"
        subprocess.run(launch_command, shell=True)
        return True
    except Exception as e:
        logging.error(f"Error launching app: {str(e)}")
        return False

def get_package_name(apk_path):
    try:
        aapt_command = f"aapt dump badging {apk_path} | grep package | awk '{{print $2}}' | sed s/name=//g | sed s/\'/\"/g"
        output = subprocess.check_output(aapt_command, shell=True, universal_newlines=True)
        return output.strip()
    except Exception as e:
        logging.error(f"Error getting package name: {str(e)}")
        return ""
