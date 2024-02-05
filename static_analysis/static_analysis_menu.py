# static_analysis_menu.py

from utils import app_display, user_prompts, logging_utils
from . import manifest_analysis, permission_analyzer, static_analysis
from virustotal import vt_requests

# Display the static analysis menu and handle user interaction.
def show_menu():
    while True:
        print(app_display.format_menu_title("Static Analysis Menu"))
        print(app_display.format_menu_option(1, "Display Available APK Files"))
        print(app_display.format_menu_option(2, "Decompile APK File"))
        print(app_display.format_menu_option(3, "Display APK Hashes"))
        print(app_display.format_menu_option(4, "Perform Static Analysis"))
        print(app_display.format_menu_option(5, "Perform Permission Analysis"))
        print(app_display.format_menu_option(6, "Check if samples has been perivously analyzed"))
        print(app_display.format_menu_option(0, "Return to Main Menu"))
        menu_choice =  user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(6)])
    
        # Display APK Files
        if menu_choice == '1':
            app_display.display_apk_files()
        
        # Decompile APK file
        if menu_choice == '2':
            static_analysis.handle_apk_decompilation()

        # Display APK Hashes
        if menu_choice == '3':
            app_display.display_apk_files()
        
        # Static analysis
        elif menu_choice == '4':
            print("Static Analysis")
            apk_path = user_prompts.user_enter_apk_path()
            decompiled_apk_dir = static_analysis.apk_static_analysis(apk_path)

        # Permission analysis
        elif menu_choice == '5':
            print("Permission Analysis")
            apk_path = user_prompts.user_enter_apk_path()
            decompiled_apk_dir = static_analysis.apk_static_analysis(apk_path)

        # Check Previously Analyzed
        elif menu_choice == '6':
            print(app_display.format_menu_title("Check If Previously Analyzed"))
            static_analysis.check_analyzed_by_apk_path()

        # Exit
        elif menu_choice == '0':
            break
        
        else:
            print("Invalid option. Please try again.")
        
        user_prompts.pause_until_keypress()
