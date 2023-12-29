import zipfile
import subprocess
import logging
import os

# Constants
LOG_FILE = 'logs/utils.log'
ANALYSIS_RESULTS_DIR = 'analysis_results'
DEX2JAR_TOOL = 'd2j-dex2jar'
APK_TOOL = 'apktool'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def create_output_directory():
    """
    Create the directory for analysis results if it doesn't exist.
    """
    try:
        os.makedirs(ANALYSIS_RESULTS_DIR, exist_ok=True)
    except OSError as e:
        print(f"Error creating directory: {e}")

def save_results(apk_path, manifest_data):
    """
    Save the analysis results to a file.

    Args:
        apk_path (str): The path to the APK file.
        manifest_data (dict): The analyzed data to be saved.
    """
    try:
        create_output_directory()
        output_file = os.path.join(ANALYSIS_RESULTS_DIR, f"{os.path.splitext(os.path.basename(apk_path))[0]}_analysis_results.txt")
        
        with open(output_file, "w") as f:
            f.write("Analysis Results:\n")
            f.write(f"APK Name: {os.path.basename(apk_path)}\n")
            
            # Write additional analysis data here
            
        print(f"Analysis results saved to {output_file}")

    except Exception as e:
        print(f"Error saving analysis results: {e}")


def copy_android_manifest(apk_path):
    """
    Copy AndroidManifest.xml content to a text file.

    Args:
        apk_path (str): The APK file path.
    """
    output_path = os.path.join(ANALYSIS_RESULTS_DIR, 'AndroidManifest.txt')

    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            with apk_zip.open('AndroidManifest.xml') as manifest_file:
                manifest_content = manifest_file.read().decode('utf-8')

        with open(output_path, "w", encoding="utf-8") as output_file:
            output_file.write(manifest_content)

        print(f"AndroidManifest.xml successfully copied to {output_path}")

    except FileNotFoundError as e:
        logging.error(f"Error: {e}.")

    except Exception as e:
        logging.error(f"Error copying AndroidManifest.xml: {e}")

def decompile_apk(apk_path):
    """
    Decompile an APK file.

    Args:
        apk_path (str): The path to the APK file.
    """
    try:
        output_directory = os.path.splitext(apk_path)[0]
        subprocess.run([APK_TOOL, "d", apk_path, "-o", output_directory], check=True)
        print(f"APK decompiled successfully. Output directory: {output_directory}")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error decompiling APK: {e}")

def generate_jar(apk_path):
    """
    Generate a JAR file from an APK file.

    Args:
        apk_path (str): The path to the APK file.

    Returns:
        str: The path to the generated JAR file, or None if an error occurred.
    """
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
    """
    Analyze a JAR file and return a list of classes found.

    Args:
        apk_path (str): The path to the APK file.

    Returns:
        list: A list of class file names found in the JAR.
    """
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
