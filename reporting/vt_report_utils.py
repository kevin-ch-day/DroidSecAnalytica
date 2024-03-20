from tabulate import tabulate

def write_section_title_to_file(title, file):
    """Writes a section title with additional padding for better visibility."""
    file.write(f"\n{' ' + title.upper() + ' ':=^60}\n")

def write_table_section_to_file(title, data, file, table_format="fancy_grid"):
    """Writes a section as a table to the file."""
    if title:
        write_section_title_to_file(title, file)
    
    if not data or len(data) <= 1:
        file.write("No data available.\n")
        return
    
    table = tabulate(data, headers="firstrow", tablefmt=table_format)
    file.write(table + '\n')

def write_list_section_to_file(title, list_items, file, as_table=False):
    """Writes a section as a list to the file."""
    if title:
        write_section_title_to_file(title, file)
    
    if not list_items:
        file.write("No items to display.\n")
        return
    
    if as_table:
        headers = ["Items"]
        table = tabulate([[item] for item in list_items], headers=headers, tablefmt="fancy_grid")
        file.write(table + '\n')
    else:
        for item in list_items:
            file.write(f"- {item}\n")

def write_dictionary_section_to_file(title, dictionary, file, exclude_keys=None, as_table=False):
    """Writes a section as a dictionary to the file."""
    if title:
        write_section_title_to_file(title, file)
    
    exclude_keys = exclude_keys or []
    filtered_dict = {k: v for k, v in dictionary.items() if k not in exclude_keys}
    
    if not filtered_dict:
        file.write("No details available.\n")
        return
    
    if as_table:
        headers = ["Key", "Value"]
        table = tabulate(filtered_dict.items(), headers=headers, tablefmt="fancy_grid")
        file.write(table + '\n')
    else:
        for key, value in sorted(filtered_dict.items()):
            file.write(f"{key.replace('_', ' ').capitalize()}: {value}\n")

def write_key_value_pair_to_file(key, value, file, separator=": "):
    """Writes a single key-value pair to the file."""
    file.write(f"{key.replace('_', ' ').capitalize()}{separator}{value}\n")

def write_nested_dictionary_to_file(title, dictionary, file, level=0, exclude_keys=None):
    """Recursively writes nested dictionaries to the file."""
    if title:
        write_section_title_to_file(title, file)
    
    exclude_keys = exclude_keys or []
    separator = ": "
    
    for key, value in sorted(dictionary.items()):
        if key in exclude_keys:
            continue
        
        indent = "  " * level
        
        if isinstance(value, dict):
            file.write(f"{indent}{key.replace('_', ' ').capitalize()}: \n")
            write_nested_dictionary_to_file(None, value, file, level + 1, exclude_keys)
        else:
            file.write(f"{indent}{key.replace('_', ' ').capitalize()}{separator}{value}\n")
