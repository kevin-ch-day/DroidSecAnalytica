# static_analysis_menu.py

import os

from utils import app_display, user_prompts, app_utils, hash_utils
from . import static_analysis

# Display the static analysis menu and handle user interaction.
def show_menu():
    while True:
        print(app_display.format_menu_title("Static Analysis Menu"))
        print(app_display.format_menu_option(1, "Display Available APK Files"))
        print(app_display.format_menu_option(2, "Display APK Hash"))
        print(app_display.format_menu_option(3, "Decompile APK File"))
        print(app_display.format_menu_option(4, "Perform Static Analysis"))
        print(app_display.format_menu_option(0, "Return to Main Menu"))
        menu_choice =  user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(6)])
    
        # Display APK Files
        if menu_choice == "1":
            app_display.display_apk_files()

        # Display APK Hash
        elif menu_choice == '2':
            apk_path = app_utils.android_apk_selection()
            if apk_path:
                print("Calculating hashes for APK file:", apk_path)
                hash_utils.calculate_hashes(apk_path)

            else:
                print("No APK file selected.")
        
        # Decompile APK file
        elif menu_choice == '3':
            static_analysis.handle_apk_decompilation()
                   
        # Static analysis
        elif menu_choice == '4':
            print("Static Analysis")
            manifest_directories = []

            # Iterate through directories in the output directory
            for dir_name in os.listdir('output'):
                dir_path = os.path.join('output', dir_name)
                
                # Check if it's a directory and contains 'AndroidManifest.xml'
                if os.path.isdir(dir_path) and 'AndroidManifest.xml' in os.listdir(dir_path):
                    manifest_directories.append(dir_name)

            print("\n** Decompiled APK files **")
            for index, directory in enumerate(manifest_directories, start=1):
                print(f"[{index}] {directory}")

            print("[0] Exit")

             # Prompt the user to select an APK file to analyze
            while True:
                try:
                    choice = int(input("\nSelect: "))
                    if 1 <= choice <= len(manifest_directories):
                        selected_decompiled_apk = os.path.join('output', manifest_directories[choice - 1])
                        static_analysis.run_analysis(selected_decompiled_apk)
                    
                    elif choice == 0:
                        break

                    else:
                        print("Invalid selection. Please enter a number within the range.")
                
                except ValueError:
                    print("Invalid input. Please enter a valid number.")
        
        # Exit
        elif menu_choice == '0':
            break
        
        user_prompts.pause_until_keypress()