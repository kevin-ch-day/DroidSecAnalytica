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

def display_tables_info(database_tables_info):
    if not database_tables_info:
        print("No table information available.")
        return

    # Define column headers
    table_header = "Table Name"
    columns_header = "Columns"
    rows_header = "Rows"
    size_mb_header = "Size (MB)"

    # Calculate column widths based on headers and data
    max_table_len = max(len(table_header), max(len(table[0]) for table in database_tables_info)) + 5
    max_columns_len = max(len(columns_header), max(len(str(table[1])) for table in database_tables_info)) + 5
    max_rows_len = max(len(rows_header), max(len(str(table[2])) for table in database_tables_info)) + 5
    max_size_mb_len = max(len(size_mb_header), max(len(str(table[3])) for table in database_tables_info)) + 5

    # Format the headers with proper alignment and padding
    table_header = table_header.ljust(max_table_len)
    columns_header = columns_header.ljust(max_columns_len)
    rows_header = rows_header.ljust(max_rows_len)
    size_mb_header = size_mb_header.ljust(max_size_mb_len)

    # Print the table headers
    print(f"\n{table_header} | {columns_header} | {rows_header} | {size_mb_header}")
    print("-" * (max_table_len + max_columns_len + max_rows_len + max_size_mb_len + 10))

    # Print table information with proper formatting
    for table_name, num_columns, num_rows, size_mb in database_tables_info:
        table_name = table_name.ljust(max_table_len)
        num_columns = str(num_columns).ljust(max_columns_len)
        num_rows = str(num_rows).ljust(max_rows_len)
        size_mb = str(size_mb).ljust(max_size_mb_len)

        print(f"{table_name} | {num_columns} | {num_rows} | {size_mb}")

def display_query_statistics(query_stats):
    if query_stats:
        print("\nQuery Statistics:")
        for stat in query_stats:
            print(f"{stat[0]}: {stat[1]}")
    else:
        print("No query statistics available.")

def display_disk_usage(disk_usage):
    if disk_usage:
        # Header
        print("\nDisk Usage Report:")
        header = f"{'Table':<30} | {'Data Size (MB)':>15} | {'Index Size (MB)':>15} | {'Total Size (MB)':>15}"
        print(header)
        print("-" * len(header))

        # Data rows
        for usage in disk_usage:
            table, data_size, index_size, total_size = usage
            print(f"{table:<30} | {data_size:>15} | {index_size:>15} | {total_size:>15}")

        # Footer
        print("-" * len(header))
    else:
        print("No disk usage data available.")

def display_thread_information(thread_info):
    if thread_info:
        print("\nThread Information:")
        
        # Formatting for a neat tabular display
        max_metric_length = max(len(info[0]) for info in thread_info)
        for metric, value in thread_info:
            print(f"{metric:<{max_metric_length}} : {value}")

    else:
        print("No thread information available.")
