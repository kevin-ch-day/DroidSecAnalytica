import os
import zipfile
import subprocess
import logging

# Constants
LOG_FILE = 'logs/jar_utils.log'
ANALYSIS_RESULTS_DIR = 'output'
DEX2JAR_TOOL = 'd2j-dex2jar'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def generate_jar(apk_path):
    try:
        output_dir = os.path.splitext(apk_path)[0]
        jar_path = f"{output_dir}-dex2jar.jar"

        subprocess.run([DEX2JAR_TOOL, apk_path, "-o", jar_path], check=True)

        print(f"Successfully generated JAR file: {jar_path}")
        return jar_path

    except subprocess.CalledProcessError as e:
        logging.error(f"Error generating JAR file: {e}")
        return None
    
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return None

def analyze_jar(apk_path):
    jar_path = f"{apk_path[:-4]}-dex2jar.jar"
    classes_found = []

    try:
        with zipfile.ZipFile(jar_path, 'r') as zipped_file:
            classes_found = [zipped_file_info.filename for zipped_file_info in zipped_file.infolist() if zipped_file_info.filename.endswith('.class')]

        return classes_found

    except zipfile.BadZipfile as e:
        logging.error(f"Error analyzing JAR file {jar_path}: {e}")
        return []
    
    except Exception as e:
        logging.error(f"Unexpected error analyzing JAR file {jar_path}: {e}")
        return []