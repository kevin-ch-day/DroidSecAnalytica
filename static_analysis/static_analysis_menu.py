from utils import app_display, user_prompts, logging_utils
from . import manifest_analysis, permission_analyzer, static_analysis

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
            print(app_display.format_menu_title("Static Analysis"))
            print(app_display.format_menu_option(1, "Submit APK"))
            print(app_display.format_menu_option(2, "Submit Hash"))
            print(app_display.format_menu_option(3, "Return to Menu"))
            user_options = ['1', '2', '3']
            user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", user_options)
            if user_choice == '1':
                static_analysis.static_analysis_apk()

            elif user_choice == '2':
                static_analysis.static_analysis_hash()

            elif user_choice == '3':
                return

        # Permission analysis
        elif menu_choice == '5':
            print(app_display.format_menu_title("Permission Analysis"))
            print(app_display.format_menu_option(1, "Submit APK"))
            print(app_display.format_menu_option(2, "Submit Hash"))
            print(app_display.format_menu_option(3, "Return to Menu"))
            user_options = ['1', '2', '3']
            user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", user_options)
            if user_choice == '1':
                static_analysis.apk_path_permissions_analysis()

            elif user_choice == '2':
                static_analysis.hash_permissions_analysis()

            elif user_choice == '3':
                return

        # Check Previously Analyzed
        elif menu_choice == '6':
            print(app_display.format_menu_title("Check If Previously Analyzed"))
            print(app_display.format_menu_option(1, "Check by APK Path"))
            print(app_display.format_menu_option(2, "Check by Hash IOC"))
            print(app_display.format_menu_option(3, "Return to Menu"))
            user_options = ['1', '2', '3']
            user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", user_options)
            if user_choice == '1':
                static_analysis.check_analyzed_by_apk_path()

            elif user_choice == '2':
                static_analysis.check_analyzed_by_hash_ioc()

            elif user_choice == '3':
                return

        # Exit
        elif menu_choice == '0':
            break
        
        else:
            print("Invalid option. Please try again.")
        user_prompts.pause_until_keypress()
