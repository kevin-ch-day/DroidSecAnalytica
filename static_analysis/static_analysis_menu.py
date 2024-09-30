# static_analysis_menu.py

import os
from typing import List

from utils import app_display, user_prompts, app_utils, utils_func
from . import static_analysis

def display_available_apk_files():
    # Display available APK files using the app_display utility
    app_display.display_apk_files()

def display_apk_hash():
    # Display the hash of the selected APK file
    apk_path = app_utils.android_apk_selection()
    if apk_path:
        print("Calculating hashes for APK file:", apk_path)
        utils_func.calculate_hashes(apk_path)
    else:
        print("No APK file selected.")

def decompile_apk_file():
    # Decompile an APK file using static_analysis utility
    static_analysis.handle_apk_decompilation()

def perform_static_analysis():
    # Perform static analysis on decompiled APK files
    manifest_directories = get_manifest_directories('output')

    if not manifest_directories:
        print("\nNo decompiled APK files found...")
    else:
        display_decompiled_apk_files(manifest_directories)

        # Prompt user to select a decompiled APK for analysis
        try:
            choice = int(input("\nSelect: "))
            if 1 <= choice <= len(manifest_directories):
                selected_decompiled_apk = os.path.join('output', manifest_directories[choice - 1])
                static_analysis.run_analysis(selected_decompiled_apk)
            elif choice == 0:
                return
            else:
                print("Invalid selection. Please enter a number within the range.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")


def get_manifest_directories(directory: str) -> List[str]:
    # Retrieve directories containing 'AndroidManifest.xml'
    manifest_dirs = []
    try:
        for dir_name in os.listdir(directory):
            dir_path = os.path.join(directory, dir_name)
            # Check if it's a directory and contains 'AndroidManifest.xml'
            if os.path.isdir(dir_path) and 'AndroidManifest.xml' in os.listdir(dir_path):
                manifest_dirs.append(dir_name)
    except FileNotFoundError:
        print(f"\nDirectory '{directory}' not found.")
    return manifest_dirs

def display_decompiled_apk_files(directories: List[str]):
    # Display a list of decompiled APK files
    print("\n** Decompiled APK files **")
    for index, directory in enumerate(directories, start=1):
        print(f"[{index}] {directory}")
    print("[0] Exit")

def show_menu_options():
    # Display the static analysis menu options
    print(app_display.format_menu_title("Static Analysis Menu"))
    print(app_display.format_menu_option(1, "Display Available APK Files"))
    print(app_display.format_menu_option(2, "Display APK Hash"))
    print(app_display.format_menu_option(3, "Decompile APK File"))
    print(app_display.format_menu_option(4, "Perform Static Analysis"))
    print(app_display.format_menu_option(0, "Return to Main Menu"))

def handle_menu_choice(menu_choice: str):
    # Handle user selection from the static analysis menu
    menu_options = {
        '1': display_available_apk_files,
        '2': display_apk_hash,
        '3': decompile_apk_file,
        '4': perform_static_analysis
    }

    if menu_choice == '0':
        return False
    elif menu_choice in menu_options:
        menu_options[menu_choice]()
    else:
        print("Invalid choice. Please select a valid option.")

    user_prompts.pause_until_keypress()
    return True

def show_menu():
    # Display the static analysis menu and handle user interaction
    while True:
        show_menu_options()
        menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(5)])
        if not handle_menu_choice(menu_choice):
            break