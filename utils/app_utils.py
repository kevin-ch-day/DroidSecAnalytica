# app_utils.py

import os
import time
import logging
import datetime

from . import user_prompts

# Constants
LOG_FILE = 'logs/utils.log'
ANALYSIS_RESULTS_DIR = 'output'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def android_apk_selection():
    apk_files = display_apk_files()
    if not apk_files: return
    apk_choice = user_prompts.user_menu_choice("Select an APK option: ", [str(i) for i in range(1, len(apk_files)+1)])
    return apk_files[int(apk_choice) - 1]

# Displays all .apk files in the current directory
def display_apk_files():
    apk_files = [f for f in os.listdir() if f.endswith('.apk')]
    print("\nAvailable APK Files:" if apk_files else "No APK files found.")
    for i, file in enumerate(apk_files, 1):
        print(f" [{i}] {file}")
    return apk_files

def wait_for_next_batch(batch_interval):
    try:      
        # Calculate time left for the next batch after the first iteration
        time_left = batch_interval
        for j in range(3, 0, -1):
            minutes_left = time_left // 60          
            if minutes_left == 4:
                print(f"{minutes_left} minutes left.")
            elif minutes_left > 1:
                print(f"{minutes_left} minutes left.")
            elif minutes_left == 1:
                print(f"{minutes_left} minute seconds left.")
            
            time_left -= 60
            time.sleep(60)

    except KeyboardInterrupt:
        print("\nExiting.")
        exit()

def format_timestamp(timestamp, format='%Y-%m-%d %H:%M:%S'):
    # Formats a Unix timestamp into a readable date string
    try:
        return datetime.datetime.fromtimestamp(int(timestamp)).strftime(format)
    except ValueError:
        return 'Invalid Timestamp format.'