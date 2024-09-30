# utils_menu.py

import os
from utils import user_prompts, app_display, hash_preload

def utils_menu():
    while True:
        menu_title = "Utils Menu"
        menu_options = {
            1: "Load Saved Hash Data",
            2: "TODO",

        }
        app_display.display_menu(menu_title, menu_options)
        user_choice = user_prompts.user_menu_choice("\nEnter your choice: ", [str(i) for i in range(3)])

        # exit
        if user_choice == '0':
            break
        
        elif user_choice == '1':
            hash_preload.process_hash_files()

        elif user_choice == '2':
            print("TODO")
            
        else:
            print("Invalid choice. Please enter a number between 0 and 3.")

        user_prompts.pause_until_keypress()