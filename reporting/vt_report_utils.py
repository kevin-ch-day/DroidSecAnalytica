from tabulate import tabulate

def format_section_title(title):
    """Enhances section titles with additional padding for better visibility."""
    print(f"\n{' ' + title.upper() + ' ':=^60}")  # Increases width for emphasis and converts title to uppercase.

def print_table_section(title, data, table_format="fancy_grid"):
    """Allows for a more visually appealing table format and checks for empty data."""
    if title:
        format_section_title(title)
    if data and len(data) > 1:  # Ensures there's data to display beyond just the header row.
        print(tabulate(data, headers="firstrow", tablefmt=table_format))
    else:
        print("No data available.")

def print_list_section(title, list_items):
    """Introduces handling for empty lists."""
    if title:
        format_section_title(title)
    if list_items:
        for item in list_items:
            print(f"- {item}")
    else:
        print("No items to display.")

def print_dictionary_section(title, dictionary, exclude_keys=None):
    """Adds functionality to exclude certain keys and handles empty dictionaries."""
    if title:
        format_section_title(title)
    exclude_keys = exclude_keys or []
    filtered_dict = {k: v for k, v in dictionary.items() if k not in exclude_keys}
    if filtered_dict:
        for key, value in sorted(filtered_dict.items()):  # Sorts keys for consistent ordering.
            print(f"{key.replace('_', ' ').capitalize()}: {value}")
    else:
        print("No details available.")

def print_key_value_pair(key, value, separator=": "):
    """Enhances single key-value pair printing with consistent formatting."""
    print(f"{key.replace('_', ' ').capitalize()}{separator}{value}")
