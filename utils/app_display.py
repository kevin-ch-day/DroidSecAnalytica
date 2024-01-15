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

def display_app_name():
    app_name = "DroidSecAnalytica"
    tagline = "Android APK Security Analyzer"

    # ANSI Escape Codes for colors and styles
    color_blue = "\033[94m"
    color_yellow = "\033[93m"
    bold = "\033[1m"
    reset = "\033[0m"

    # Define the widths and border styles
    header_width = max(len(app_name), len(tagline)) + 6  # Adjust width based on content
    top_border = color_blue + "╔" + "═" * (header_width - 2) + "╗" + reset
    middle_border = color_blue + "╠" + "═" * (header_width - 2) + "╣" + reset
    bottom_border = color_blue + "╚" + "═" * (header_width - 2) + "╝" + reset

    # Center the app name and tagline within the borders
    app_name_header = color_yellow + bold + "║" + app_name.center(header_width - 2) + "║" + reset
    tagline_header = "║" + tagline.center(header_width - 2) + "║"

    # Print the formatted header
    print("\n" + top_border)
    print(app_name_header)
    print(middle_border)
    print(tagline_header)
    print(bottom_border)