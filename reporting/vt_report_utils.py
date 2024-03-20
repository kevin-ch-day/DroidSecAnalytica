from tabulate import tabulate

def format_section_title(title):
    print(f"\n{' ' + title.upper() + ' ':=^60}")

def print_table_section(title, data, table_format="fancy_grid"):
    if title:
        format_section_title(title)
    if data and len(data) > 1:
        print(tabulate(data, headers="firstrow", tablefmt=table_format))
    else:
        print("No data available.")

def print_list_section(title, list_items, as_table=False):
    if title:
        format_section_title(title)
    
    if not list_items:
        print("No items to display.")
        return
    
    if as_table:
        print(tabulate([item for item in list_items], headers="keys", tablefmt="fancy_grid"))
    else:
        for item in list_items:
            print(f"- {item}")

def print_dictionary_section(title, dictionary, exclude_keys=None, as_table=False):
    if title:
        format_section_title(title)
    exclude_keys = exclude_keys or []
    filtered_dict = {k: v for k, v in dictionary.items() if k not in exclude_keys}
    if not filtered_dict:
        print("No details available.")
        return
    if as_table:
        print(tabulate([{'Key': k, 'Value': v} for k, v in filtered_dict.items()], headers="keys", tablefmt="fancy_grid"))
    else:
        for key, value in sorted(filtered_dict.items()):
            print(f"{key.replace('_', ' ').capitalize()}: {value}")

def print_key_value_pair(key, value, separator=": "):
    print(f"{key.replace('_', ' ').capitalize()}{separator}{value}")

def print_nested_dictionary(title, dictionary, level=0, exclude_keys=None):
    """Recursively prints nested dictionaries."""
    if title:
        format_section_title(title)
    exclude_keys = exclude_keys or []
    separator = ": "  # Define the separator here
    for key, value in sorted(dictionary.items()):
        if key in exclude_keys:
            continue
        indent = "  " * level
        if isinstance(value, dict):
            print(f"{indent}{key.replace('_', ' ').capitalize()}:")
            print_nested_dictionary(None, value, level + 1, exclude_keys)
        else:
            print(f"{indent}{key.replace('_', ' ').capitalize()}{separator}{value}")
