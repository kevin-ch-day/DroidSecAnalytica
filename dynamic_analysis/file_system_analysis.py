# file_system_analysis.py

from utils import logging_utils
import subprocess

# Constants
LOG_FILE = 'logs/android_file_system_analysis.log'

# Configure logging for Android file system analysis
logging_utils.configure_logging(LOG_FILE)

def analyze_android_file_system():
    try:
        logging_utils.log_info("Starting Android file system analysis...")
        
        # List of directories prone to Android banking trojan infections
        search_directories = [
            "/data/data",
            "/sdcard/Android/data",
            "/sdcard/Android/obb",
            "/system/app",
            "/system/priv-app",
            "/data/app",
            "/data/data/com.android.providers.telephony",
            "/data/data/com.android.mms",
            "/data/data/com.android.smspush"
        ]

        # Connect to the Android device
        logging_utils.log_info("Connecting to the Android device...")
        subprocess.run(["adb", "start-server"])

        for directory in search_directories:
            logging_utils.log_info(f"Analyzing files and directories in {directory}:")
            
            # Use adb shell to list files and directories in the specified path
            adb_command = f"adb shell ls -R {directory}"
            result = subprocess.run(adb_command, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                file_listing = result.stdout
                logging_utils.log_info(file_listing)
            else:
                logging_utils.log_error(f"Failed to list files and directories in {directory}")

        # Disconnect from the Android device
        subprocess.run(["adb", "kill-server"])
        logging_utils.log_info("Disconnected from the Android device.")

        logging_utils.log_info("Android file system analysis completed.")

    except Exception as e:
        logging_utils.log_error(f"Android file system analysis failed with error: {str(e)}")
