import logging

from . import dynamic_analysis
from utils import app_display, user_prompts

# Constants
LOG_FILE = 'logs/dynamic_analysis.log'

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def dynamic_analysis_menu():
    print(app_display.format_menu_title("Dynamic Analysis Menu"))
    print(app_display.format_menu_option(1, "Run Dynamic Analysis"))
    print(app_display.format_menu_option(0, "Back to Main Menu"))
    menu_choice = user_prompts.user_menu_choice("\nEnter your choice: ", ['1', '0'])
    if menu_choice == '1':
        apk_path = input("Enter the path to the APK: ").strip()
        dynamic_analysis.run_analysis(apk_path)