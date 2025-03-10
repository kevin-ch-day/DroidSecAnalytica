# app_display.py

import datetime
import os

from . import app_utils

APP_NAME = "DroidSecAnalytica"

def display_apk_files(directory='input'):
    try:
        apk_files = [f for f in os.listdir(directory) if f.endswith('.apk')]
        apk_files.sort()  # Sort alphabetically
        num_files = len(apk_files)

        if num_files == 0:
            print("No APK files found.")
            return False

        print("\nAvailable APK Files:")
        page_size = 10  # Number of files to display per page
        num_pages = (num_files + page_size - 1) // page_size

        for page in range(num_pages):
            start_index = page * page_size
            end_index = min((page + 1) * page_size, num_files)
            print(f"Page {page + 1}/{num_pages}:")
            for i, file in enumerate(apk_files[start_index:end_index], start=start_index + 1):
                print(f" [{i}] {file}")

            if num_pages > 1 and page < num_pages - 1:
                input("Press Enter to view next page...")

        return True

    except FileNotFoundError:
        print("Directory not found.")
        return False
    
    except PermissionError:
        print("Permission denied.")
        return False

def display_menu(menu_title, menu_options):
    print(format_menu_title(menu_title))
    for key, option in menu_options.items():
        print(format_menu_option(key, option))
    print(format_menu_option(0, "Return"))

# Display disk usgae
def display_disk_usage(disk_usage):
    if not disk_usage:
        print("No disk usage data available.")
        return
    print(f"\n{'Database'.ljust(20)} | {'Size in MB'.rjust(10)}")
    print("-" * 33)
    for db_name, size_mb in disk_usage:
        print(f"{db_name.ljust(20)} | {str(size_mb).rjust(10)}")

# Display a greeting message to the user
def display_greeting():
    current_time = datetime.datetime.now()
    greeting = "Good morning" if 5 <= current_time.hour < 12 else \
               "Good afternoon" if 12 <= current_time.hour < 18 else \
               "Good evening"

    formatted_time = current_time.strftime('%I:%M %p on %A, %B %d, %Y')
    print(f"\n {greeting}! Welcome to {APP_NAME}.")
    print(f" The current time is {formatted_time}.")

# Formats the menu title with borders and alignment
def format_menu_title(title: str, width: int = 50, border_char: str = "=", align: str = 'center', padding: int = 1) -> str:
    # Adjust width to be at least as long as the title plus padding
    adjusted_width = max(width, len(title) + padding * 2)

    # Align the title
    aligned_title = title.ljust(adjusted_width) if align == 'left' \
                    else title.rjust(adjusted_width) if align == 'right' \
                    else title.center(adjusted_width)

    # Add padding and create borders
    padded_title = f"{' ' * padding}{aligned_title}{' ' * padding}"
    border = border_char * adjusted_width
    return f"\n {border}\n {padded_title}\n {border}\n"

# Formats a menu option with a dynamic adjustment for the option number spacing
def format_menu_option(number: int, description: str, number_width: int = 3, right_align: bool = False) -> str:
    if not isinstance(number, int) or not isinstance(description, str) or not isinstance(number_width, int):
        raise ValueError("Invalid input types for format_menu_option")

    formatted_number = str(number)
    # Adjust spacing based on the number width
    padding = max(number_width - len(formatted_number), 0)
    # Right-align the number if specified
    formatted_number = formatted_number.rjust(number_width) if right_align else formatted_number

    # Construct the option string with dynamic spacing
    return f" [{formatted_number}]" + " " * (padding + 1) + description

# Display application name
def display_app_name():
    tagline = "Android APK Security Analyzer"

    # ANSI Escape Codes for colors and styles
    color_blue = "\033[94m"
    color_yellow = "\033[93m"
    bold = "\033[1m"
    reset = "\033[0m"

    # Enable ANSI support on Windows
    app_utils.enable_windows_ansi_support()

    # Define the widths and border styles
    header_width = max(len(APP_NAME), len(tagline)) + 6  # Adjust width based on content
    top_border = color_blue + "╔" + "═" * (header_width - 2) + "╗" + reset
    middle_border = color_blue + "╠" + "═" * (header_width - 2) + "╣" + reset
    bottom_border = color_blue + "╚" + "═" * (header_width - 2) + "╝" + reset

    # Center the app name and tagline within the borders
    app_name_header = color_yellow + bold + "║" + APP_NAME.center(header_width - 2) + "║" + reset
    tagline_header = "║" + tagline.center(header_width - 2) + "║"

    # Print the formatted header
    print("\n " + top_border)
    print(" " + app_name_header)
    print(" " + middle_border)
    print(" " + tagline_header)
    print(" " + bottom_border)
