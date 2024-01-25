# file_system_analysis.py

from utils import logging_utils
import subprocess

# Constants
LOG_FILE = 'logs/android_file_system_analysis.log'

# Configure logging for Android file system analysis
logging_utils.setup_logger(LOG_FILE)

def analyze_android_file_system():
    try:
        print("Starting Android file system analysis...")
        
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

        print("Connecting to the Android device...")
        subprocess.run(["adb", "start-server"], check=True)

        for directory in search_directories:
            try:
                logging_utils.log_info(f"Analyzing files and directories in {directory}...")
                
                result = subprocess.run(["adb", "shell", "ls", "-R", directory], capture_output=True, text=True, check=True)
                
                # Consider processing or summarizing result.stdout before logging
                print("Directory analysis completed.")
                
            except subprocess.CalledProcessError as e:
                logging_utils.log_error(f"Failed to list files and directories in {directory}: {str(e)}")

        subprocess.run(["adb", "kill-server"], check=True)
        logging_utils.log_info("Disconnected from the Android device.")
        logging_utils.log_info("Android file system analysis completed.")

    except Exception as e:
        logging_utils.log_error(f"Android file system analysis failed with error: {str(e)}")
