# app_utils.py

import time
import datetime
import platform
import ctypes
import ctypes.wintypes
import subprocess
import requests
import os
from typing import Optional

# Constants
ANALYSIS_RESULTS_DIR = 'output'
ANALYSIS_INPUT_DIR = 'input'

def android_apk_selection():
    # Try to list APK files in the specified directory
    try:
        apk_files = [f for f in os.listdir(ANALYSIS_INPUT_DIR) if f.endswith('.apk')]
        apk_files.sort()  # Sort alphabetically
        num_files = len(apk_files)

        # If no APK files found, print a message and return None
        if num_files == 0:
            print("No APK files found.")
            return None

        # Display APK files with pagination
        print("\nAvailable APK Files:")
        page_size = 10  # Number of files to display per page
        num_pages = (num_files + page_size - 1) // page_size

        for page in range(num_pages):
            start_index = page * page_size
            end_index = min((page + 1) * page_size, num_files)
            print(f"Page {page + 1}/{num_pages}:")
            for i, file in enumerate(apk_files[start_index:end_index], start=start_index + 1):
                print(f" [{i}] {file}")

            # If there are multiple pages, prompt user to view next page
            if num_pages > 1 and page < num_pages - 1:
                input("Press Enter to view next page...")

        # Prompt user to select an APK file
        apk_choice = input("Select an APK option: ")
        apk_index = int(apk_choice) - 1

        # Validate user choice
        if apk_index < 0 or apk_index >= num_files:
            print("Invalid selection.")
            return None

        # Return the selected APK file path
        return os.path.join(ANALYSIS_INPUT_DIR, apk_files[apk_index])

    except FileNotFoundError:
        print("Directory not found.")
        return None
    
    except PermissionError:
        print("Permission denied.")
        return None

def enable_windows_ansi_support():
    if platform.system() == "Windows":
        stdout_handle = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.wintypes.DWORD()
        ctypes.windll.kernel32.GetConsoleMode(stdout_handle, ctypes.byref(mode))
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        ctypes.windll.kernel32.SetConsoleMode(stdout_handle, new_mode)

def check_network_connection():
    ip_address = "8.8.8.8"
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip_address]

    try:
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = response.returncode == 0
        return result
    except Exception as e:
        print(f"[Error] checking network connection: {e}")
        return False

def check_virustotal_connection():
    url = "https://www.virustotal.com"
    try:
        response = requests.get(url)
        result = response.status_code == 200
        return result
    except requests.RequestException as e:
        print(f"[Error] Request to VirusTotal failed: {e}")
        return False

def format_timestamp(timestamp, format='%Y-%m-%d %H:%M:%S'):
    try:
        formatted_time = datetime.datetime.fromtimestamp(int(timestamp)).strftime(format)
        return formatted_time
    except (ValueError, TypeError):
        print(f"[Error] Invalid timestamp format.")
        return 'Invalid Timestamp format.'

def format_seconds_to_dhms(seconds):
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"

def pause_with_updates(wait_time: int, update_interval: int = 60, display_text: Optional[str] = None):
    # Pauses execution while providing updates on the remaining time.

    try:
        if not display_text:
            display_text = "Pausing..." if update_interval == 1 else "Waiting for next batch..."
        print(display_text)

        for remaining_time in range(wait_time, 0, -update_interval):
            minutes, seconds = divmod(remaining_time, 60)
            time_display = f"Time remaining: {minutes:02d} minutes {seconds:02d} seconds"
            print(f"\r{time_display}", end="")
            # Sleep for the update_interval or the remaining time if it's less than the update_interval
            time.sleep(min(update_interval, remaining_time))

        print("\nProcess completed.")
    except KeyboardInterrupt:
        print("\nProcess interrupted by user.")