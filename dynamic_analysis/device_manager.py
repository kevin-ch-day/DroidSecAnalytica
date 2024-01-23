
import subprocess
import logging

# Constants
LOG_FILE = 'logs/device_manager.log'

# Configure logging for device management
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_devices():
    try:
        adb_command = "adb devices"
        output = subprocess.check_output(adb_command, shell=True, universal_newlines=True)
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
    try:
        emulator_dir = tempfile.mkdtemp()
        emulator_command = f"emulator -avd <YOUR_AVD_NAME>"
        subprocess.run(emulator_command, shell=True, cwd=emulator_dir)
        return True
    except Exception as e:
        logging.error(f"Error starting emulator: {str(e)}")
        return False

def stop_emulator():
    try:
        stop_command = "adb emu kill"
        subprocess.run(stop_command, shell=True)
        return True
    except Exception as e:
        logging.error(f"Error stopping emulator: {str(e)}")
        return False
