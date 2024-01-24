import os
import subprocess
import platform
from typing import Optional

from utils import app_utils, app_display, user_prompts, logging_utils
from . import manifest_analysis, vt_analysis

# Constants for file paths
ANALYSIS_OUTPUT_DIR = 'output'

# Display the static analysis menu and handle user interaction.
def static_menu():
    while True:
        print(app_display.format_menu_title("Static Analysis Menu"))
        print(app_display.format_menu_option(1, "Check if sample has been analyzed"))
        print(app_display.format_menu_option(2, "Decompile APK file"))
        print(app_display.format_menu_option(3, "Perform static analysis"))
        print(app_display.format_menu_option(4, "Perform permission Analysis"))
        print(app_display.format_menu_option(5, "Perform virusTotal.com Analysis"))
        print(app_display.format_menu_option(6, "Display available APK Files"))
        print(app_display.format_menu_option(7, "Display APK File Hashes"))
        print(app_display.format_menu_option(1, "Check Virustotal API Key"))
        print(app_display.format_menu_option(0, "Return to Main Menu"))
        menu_choice =  user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(11)])
        
        # Check if sample has been previously analyzed
        if menu_choice == '1':
            handle_sample_check()
        
        # Decompile APK file
        elif menu_choice == '2':
            handle_apk_decompilation()
        
        # Static analysis
        elif menu_choice == '3':
            handle_static_apk_analysis()

        # Permission analysis
        elif menu_choice == '4':
            handle_permissions_analysis()
        
        # Virustotal.com analysis
        elif menu_choice == '5':
            vt_analysis.virustotal_menu()
        
        # Display available APK Files
        elif menu_choice == '6':
            handle_permissions_analysis()
        
        # Display APK File Hashes
        elif menu_choice == '7':
            app_utils.display_apk_files()
        
        elif menu_choice == '0':
            break
        
        else:
            print("Invalid option. Please try again.")
        user_prompts.pause_until_keypress()

def display_sample_check_menu():
    print(app_display.format_menu_title("Check Previously Analyzed"))
    print(app_display.format_menu_option(1, "Check by APK Path"))
    print(app_display.format_menu_option(2, "Check by Hash IOC"))
    print(app_display.format_menu_option(3, "Return to Menu"))
    user_options = ['1', '2', '3']
    user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", user_options)
    if user_choice == '1':
        check_analyzed_by_apk_path()

    elif user_choice == '2':
        check_analyzed_by_hash_ioc()

    elif user_choice == '3':
        return

def check_analyzed_by_apk_path():
    apk_path = user_prompts.user_enter_apk_path()
    perform_preanalysis(apk_path)

def check_analyzed_by_hash_ioc():
    hash_ioc = user_prompts.user_enter_hash_ioc()
    # Check if the hash IOC has records

# Run static analysis
def perform_preanalysis(apk_path: str):
    apk_hashes = app_utils.calculate_hashes(apk_path)
    app_display.display_hashes(apk_path, apk_hashes)
    
    if not database_functions.check_for_hash_record(apk_hashes):
        # Hash does not have a record in malware_hashes
        print("IOC hash does not have a record")
        file_basename = os.path.basename(apk_path)
        file_size_bytes = os.path.getsize(apk_path)
        database_functions.create_apk_record(file_basename, file_size_bytes, apk_hashes["MD5"], apk_hashes["SHA1"], apk_hashes["SHA256"])
        
        if not database_functions.check_if_hash_analyzed(apk_hashes):
            # Hash has not been analyzed
            print("IOC hash has not been analyzed")
            perform_full_analysis(apk_path)

        else:
            # Hash has been analyzed
            print("IOC hash has already been analyzed")
            return

    else:
        # Hash has a record in malware_hashes
        print("IOC hash has a record")

    input("Press any button to continue...")

def handle_apk_decompilation():
    apk_path = app_utils.android_apk_selection()
    decompile_apk(apk_path)

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

# Run static analysis
def perform_static_analysis(apk_path: str):
    file_basename = os.path.basename(apk_path)
    try:
        output_directory = decompile_apk(apk_path, f"{ANALYSIS_OUTPUT_DIR}/{os.path.splitext(file_basename)[0]}")
        if output_directory:
            manifest_path = os.path.join(output_directory, "AndroidManifest.xml")
            manifest_data = manifest_analysis.analyze_android_manifest(manifest_path)
            if manifest_data:
                manifest_element = manifest_analysis.analyze_manifest_element(manifest_path)
                
        else:
            print("Error decompiling the APK file")
        
        # Virustotal.com scan
        virustotal_analysis(apk_path)

    except Exception as e:
        logging_utils.log_error(f"Error during static analysis: {e}")