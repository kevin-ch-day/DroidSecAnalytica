import subprocess
import platform
from typing import Optional

from utils import app_utils, logging_utils

def handle_apk_decompilation():
    apk_path = app_utils.android_apk_selection()
    decompile_apk(apk_path, 'output')

def decompile_apk(apk_path: str, output_directory: str) -> Optional[str]:
    # Check OS and exit if Windows
    if platform.system() == "Windows":
        logging_utils.log_error("This function cannot be executed on Windows.")
        return None

    # Check if OS is Kali Linux or Ubuntu
    if "kali" in platform.version().lower() or "ubuntu" in platform.version().lower():
        try:
            subprocess.run(["apktool", "d", "-f", apk_path, "-o", output_directory], check=True)
            logging_utils.log_info(f"APK decompiled successfully. Output directory: {output_directory}")
            return output_directory
        except subprocess.CalledProcessError as e:
            logging_utils.log_error(f"Error decompiling APK: {e}")
            return None
    else:
        logging_utils.log_error("This function can only be executed on Kali Linux or Ubuntu.")
        return None