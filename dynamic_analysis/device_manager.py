# device_manager.py

import subprocess
from utils import logging_utils
import tempfile

def check_devices():
    try:
        adb_command = ["adb", "devices"]
        output = subprocess.check_output(adb_command, universal_newlines=True)
        if "List of devices attached" in output:
            lines = output.split('\n')
            connected_devices = [line.strip() for line in lines[1:] if line.strip()]
            return len(connected_devices) > 0
        else:
            return False
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error checking connected devices: {e.output}")
        return False
    except Exception as e:
        logging_utils.log_error(f"Unexpected error checking connected devices: {e}")
        return False

def start_emulator(avd_name):
    try:
        emulator_dir = tempfile.mkdtemp()
        emulator_command = ["emulator", "-avd", avd_name]
        subprocess.run(emulator_command, cwd=emulator_dir)
        logging_utils.log_info(f"Emulator {avd_name} started successfully.")
        return True
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error starting emulator {avd_name}: {e.output}")
        return False
    except Exception as e:
        logging_utils.log_error(f"Unexpected error starting emulator {avd_name}: {e}")
        return False

def stop_emulator():
    try:
        subprocess.run(["adb", "emu", "kill"], check=True)
        logging_utils.log_info("Emulator stopped successfully.")
        return True
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error stopping emulator: {e.output}")
        return False
    except Exception as e:
        logging_utils.log_error(f"Unexpected error stopping emulator: {e}")
        return False

def restart_device():
    try:
        subprocess.run(["adb", "reboot"], check=True)
        logging_utils.log_info("Device restarted successfully.")
        return True
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error restarting device: {e.output}")
        return False
    except Exception as e:
        logging_utils.log_error(f"Unexpected error restarting device: {e}")
        return False

def get_device_info():
    try:
        device_info = {}
        for prop in ["ro.product.model", "ro.build.version.release"]:
            output = subprocess.check_output(["adb", "shell", "getprop", prop], universal_newlines=True).strip()
            device_info[prop] = output
        logging_utils.log_info("Device info retrieved successfully.")
        return device_info
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error getting device info: {e.output}")
        return {}
    except Exception as e:
        logging_utils.log_error(f"Unexpected error getting device info: {e}")
        return {}

def install_multiple_apks(apk_paths):
    try:
        for apk_path in apk_paths:
            subprocess.run(["adb", "install", apk_path], check=True)
        logging_utils.log_info(f"Successfully installed {len(apk_paths)} APKs.")
        return True
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error installing APKs: {e.output}")
        return False
    except Exception as e:
        logging_utils.log_error(f"Unexpected error installing APKs: {e}")
        return False

def capture_device_screenshot(save_path):
    try:
        subprocess.run(["adb", "shell", "screencap", "-p", "/sdcard/screenshot.png"], check=True)
        subprocess.run(["adb", "pull", "/sdcard/screenshot.png", save_path], check=True)
        logging_utils.log_info(f"Screenshot captured and saved to {save_path}.")
        return True
    except subprocess.CalledProcessError as e:
        logging_utils.log_error(f"Error capturing screenshot: {e.output}")
        return False
    except Exception as e:
        logging_utils.log_error(f"Unexpected error capturing screenshot: {e}")
        return False
