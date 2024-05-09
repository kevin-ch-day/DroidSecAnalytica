# static_analysis_menu.py

from utils import app_display, user_prompts
from permissions_analysis import record_permissions
from . import manifest_analysis, static_analysis

# Display the static analysis menu and handle user interaction.
def show_menu():
    while True:
        print(app_display.format_menu_title("Static Analysis Menu"))
        print(app_display.format_menu_option(1, "Display Available APK Files"))
        print(app_display.format_menu_option(2, "Decompile APK File"))
        print(app_display.format_menu_option(3, "Display APK Hash"))
        print(app_display.format_menu_option(4, "Perform Static Analysis"))
        print(app_display.format_menu_option(5, "Perform AndroidManifest.xml Analysis"))
        print(app_display.format_menu_option(0, "Return to Main Menu"))
        menu_choice =  user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(6)])
    
        # Display APK Files
        if menu_choice == "1":
            app_display.display_apk_files()
        
        # Decompile APK file
        if menu_choice == '2':
            static_analysis.handle_apk_decompilation()

        # Display APK Hash
        if menu_choice == '3':
            apk = app_display.display_apk_files()
            # calc and display the hash
        
        # Static analysis
        elif menu_choice == '4':
            print("Static Analysis")
            apk_path = user_prompts.user_enter_apk_path()
            decompiled_apk_dir = static_analysis.apk_static_analysis(apk_path)

        # AndroidManifest.xml Analysis
        elif menu_choice == '5':
            print("APk AndroidManifest.xml Analysis")

        # Permission analysis
        elif menu_choice == '6':
            print("Permission Analysis")
            apk_path = user_prompts.user_enter_apk_path()
            decompiled_apk_dir = static_analysis.apk_static_analysis(apk_path)
            #permission_analyzer.extract_permissions(decompiled_apk_dir)

        # Exit
        elif menu_choice == '0':
            break
        
        user_prompts.pause_until_keypress()
