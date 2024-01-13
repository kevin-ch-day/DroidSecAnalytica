import os

# Display APK Files
def display_apk_files():
    apk_files = [f for f in os.listdir() if f.endswith('.apk')]
    print("\nAvailable APK Files:" if apk_files else "No APK files found.")
    for i, file in enumerate(apk_files, 1):
        print(f" [{i}] {file}")
    return apk_files

# Display Application Name
def display_app_name(app_name="DroidSecAnalytica"):
    """ Display the application name in a stylish header. """
    header_width = 40
    top_border = "╔" + "═" * (header_width - 2) + "╗"
    app_name_header = "║" + app_name.center(header_width - 2) + "║"
    bottom_border = "╚" + "═" * (header_width - 2) + "╝"
    print("\n" + top_border)
    print(app_name_header)
    print(bottom_border)

def list_log_files(log_directory):
    """ List all log files in the specified directory. """
    log_files = [f for f in os.listdir(log_directory) if f.endswith('.log')]
    if not log_files:
        print("No log files found.")
        return []
    for i, file in enumerate(log_files, 1):
        print(f" [{i}] {file}")
    return log_files

def view_log_file(log_directory, log_files, choice):
    """ Display the content of the selected log file. """
    file_path = os.path.join(log_directory, log_files[choice - 1])
    with open(file_path, 'r') as file:
        print(file.read())

def handle_view_logs():
    log_directory = 'output'
    log_files = list_log_files(log_directory)
    if log_files:
        try:
            choice = int(input("Enter the number of the log file to view: "))
            if 0 < choice <= len(log_files):
                view_log_file(log_directory, log_files, choice)
            else:
                print("Invalid selection.")
        except ValueError:
            print("Please enter a valid number.")

def get_user_choice(prompt, valid_choices):
    """ Get and validate user choice. """
    while True:
        choice = input(prompt).strip()
        if choice in valid_choices:
            return choice
        print("Invalid choice. Please select a valid option.")

def format_menu_title(title, width=30):
    """ Helper function to format the menu title. """
    return f"\n{title}\n" + "=" * width

def format_menu_option(number, description):
    """ Helper function to format each menu option. """
    return f" [{number}] {description}"