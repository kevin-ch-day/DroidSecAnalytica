# app_display.py

import datetime
import platform
import ctypes

APP_NAME = "DroidSecAnalytica"

# Display a greeting message to the user
def display_greeting():
    current_time = datetime.datetime.now()
    greeting = "Good morning" if 5 <= current_time.hour < 12 else \
               "Good afternoon" if 12 <= current_time.hour < 18 else \
               "Good evening"

    print(f"\n{greeting}! Welcome to {APP_NAME}.")
    print(f"The current time is {current_time.strftime('%H:%M on %A, %B %d, %Y')}.")
    print("The application is starting up, please wait...")

# Helper function to format the menu title
def format_menu_title(title, width=40, border_char="=", align='center'):
    # Ensure the width is at least as long as the title
    adjusted_width = max(width, len(title) + 4)

    # Align the title based on the align parameter
    if align == 'left':
        aligned_title = title.ljust(adjusted_width)
    elif align == 'right':
        aligned_title = title.rjust(adjusted_width)
    else:  # default to center
        aligned_title = title.center(adjusted_width)

    # Create the formatted title with decorative borders
    top_border = border_char * adjusted_width
    bottom_border = border_char * adjusted_width
    return f"\n{top_border}\n{aligned_title}\n{bottom_border}\n"

def format_menu_option(number, description, number_width=0):
    formatted_number = str(number).rjust(number_width)
    option_format = f" [{formatted_number}] {description}"
    return option_format

# Enable ANSI escape sequence support on Windows 10 and later command prompt.
def enable_windows_ansi_support():
    if platform.system() == "Windows":
        # Get standard output handle
        stdout_handle = ctypes.windll.kernel32.GetStdHandle(-11)

        # Get the current console mode
        mode = ctypes.wintypes.DWORD()
        ctypes.windll.kernel32.GetConsoleMode(stdout_handle, ctypes.byref(mode))

        # Enable ANSI escape codes
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING

        # Set the new mode
        ctypes.windll.kernel32.SetConsoleMode(stdout_handle, new_mode)

def display_app_name():
    tagline = "Android APK Security Analyzer"

    # ANSI Escape Codes for colors and styles
    color_blue = "\033[94m"
    color_yellow = "\033[93m"
    bold = "\033[1m"
    reset = "\033[0m"

    # Enable ANSI support on Windows
    enable_windows_ansi_support()

    # Define the widths and border styles
    header_width = max(len(APP_NAME), len(tagline)) + 6  # Adjust width based on content
    top_border = color_blue + "╔" + "═" * (header_width - 2) + "╗" + reset
    middle_border = color_blue + "╠" + "═" * (header_width - 2) + "╣" + reset
    bottom_border = color_blue + "╚" + "═" * (header_width - 2) + "╝" + reset

    # Center the app name and tagline within the borders
    app_name_header = color_yellow + bold + "║" + APP_NAME.center(header_width - 2) + "║" + reset
    tagline_header = "║" + tagline.center(header_width - 2) + "║"

    # Print the formatted header
    print("\n" + top_border)
    print(app_name_header)
    print(middle_border)
    print(tagline_header)
    print(bottom_border)