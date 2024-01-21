# app_display.py

import datetime
import platform
import ctypes
import os

APP_NAME = "DroidSecAnalytica"

# Display a greeting message to the user
def display_greeting():
    current_time = datetime.datetime.now()
    greeting = "Good morning" if 5 <= current_time.hour < 12 else \
               "Good afternoon" if 12 <= current_time.hour < 18 else \
               "Good evening"

    formatted_time = current_time.strftime('%I:%M %p on %A, %B %d, %Y')
    print(f"\n{greeting}! Welcome to {APP_NAME}.")
    print(f"The current time is {formatted_time}.")

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
    return f"\n{border}\n{padded_title}\n{border}\n"

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

def display_hashes(file_path, hashes):
    print("\nAPK Calculated Hashes")
    print("-" * 60)
    print(f"File  : {os.path.basename(file_path)}")
    for hash_type, hash_value in hashes.items():
        print(f"{hash_type:6}: {hash_value}")
    print("-" * 60)