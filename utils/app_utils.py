# app_utils.py

import time
import logging
import datetime
import platform
import ctypes
import subprocess
import requests

from . import user_prompts, app_display

# Constants
LOG_FILE = 'logs/utils.log'
ANALYSIS_RESULTS_DIR = 'output'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def android_apk_selection():
    apk_files = app_display.display_apk_files()
    if not apk_files:
        return
    apk_choice = user_prompts.user_menu_choice("Select an APK option: ", [str(i) for i in range(1, len(apk_files)+1)])
    return apk_files[int(apk_choice) - 1]

# Calculate time left for the next batch after the first iteration
def wait_for_next_batch(batch_interval):
    try:      
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

# Formats a Unix timestamp into a readable date string
def format_timestamp(timestamp, format='%Y-%m-%d %H:%M:%S'):
    try:
        return datetime.datetime.fromtimestamp(int(timestamp)).strftime(format)
    except ValueError:
        return 'Invalid Timestamp format.'
    
def format_seconds_to_dhms(seconds):
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"

# Enable ANSI escape sequence support on Windows 10 and later command prompt.
def enable_windows_ansi_support():
    if platform.system() == "Windows":
        # Get standard output handle
        stdout_handle = ctypes.windll.kernel32.GetStdHandle(-11)

        # Get the current console mode
        mode = ctypes.wintypes.DWORD()
        ctypes.windll.kernel32.GetConsoleMode(stdout_handle, ctypes.byref(mode))

        # Enable ANSI escape codes
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING

        # Set the new mode
        ctypes.windll.kernel32.SetConsoleMode(stdout_handle, new_mode)

def check_network_connection():
    ip_address = "8.8.8.8"
    
    # Determine the command based on the operating system
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip_address]

    try:
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = response.returncode == 0
        return result
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def check_virustotal_connection():
    url = "https://www.virustotal.com"
    try:
        response = requests.get(url)
        result = response.status_code == 200
        return result
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return False