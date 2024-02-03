# app_utils.py

import time
import datetime
import platform
import ctypes
import ctypes.wintypes
import subprocess
import requests
from typing import Optional

from . import user_prompts, app_display, logging_utils

# Constants
ANALYSIS_RESULTS_DIR = 'output'

def android_apk_selection():
    apk_files = app_display.display_apk_files()
    if not apk_files:
        return
    apk_choice = user_prompts.user_menu_choice("Select an APK option: ", [str(i) for i in range(1, len(apk_files) + 1)])
    return apk_files[int(apk_choice) - 1]

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
        logging_utils.log_error(f"An error occurred checking network connection: {e}")
        return False

def check_virustotal_connection():
    url = "https://www.virustotal.com"
    try:
        response = requests.get(url)
        result = response.status_code == 200
        return result
    except requests.RequestException as e:
        logging_utils.log_error(f"Request to VirusTotal failed: {e}")
        return False

def format_timestamp(timestamp, format='%Y-%m-%d %H:%M:%S'):
    try:
        formatted_time = datetime.datetime.fromtimestamp(int(timestamp)).strftime(format)
        return formatted_time
    except (ValueError, TypeError):
        logging_utils.log_error("Invalid timestamp format.")
        return 'Invalid Timestamp format.'

def format_seconds_to_dhms(seconds):
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"

def pause_with_updates(wait_time: int, update_interval: int = 60, display_text: Optional[str] = None):
    # Pauses execution while providing updates on the remaining time. Can be used to pause
    # with progress feedback or wait for the next batch with less frequent updates.

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