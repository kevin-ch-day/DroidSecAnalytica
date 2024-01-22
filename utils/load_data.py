# load_data.py

import logging
import os
import calendar
import re

from database import DBUtils as dbu
from . import hash_utils

def check_files(file_paths):
    """ Check if files exist and have content. """
    valid_files = []
    for file_path in file_paths:
        if not os.path.isfile(file_path):
            logging.warning(f"File not found: {file_path}")
            continue

        if os.path.getsize(file_path) == 0:
            logging.warning(f"File is empty: {file_path}")
            continue

        valid_files.append(file_path)

    return valid_files

def read_file_lines(file_path):
    """ Read and return all lines from the file. """
    with open(file_path, 'r') as file:
        return file.readlines()

def read_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.readlines()
    except FileNotFoundError:
        logging.error(f"Error: File not found - {file_path}")
    except Exception as e:
        logging.error(f"Error reading file: {e}")
    return None

def loadAndroidHashData():
    try:
        if not dbu.check_for_table('android_malware_hashes'):
            dbu.create_android_malware_hash_table()
        
        input_directory = 'input'
        files_to_parse = ['2019-README.txt', '2020-README.txt', '2021-README.txt', '2022-README.txt']
        files_to_parse = [os.path.join(input_directory, file) for file in files_to_parse]

        # Check if input directory exists
        if not os.path.isdir(input_directory):
            logging.error(f"Input directory '{input_directory}' not found.")
            return

        # Check if files exist and have content
        valid_files = check_files(files_to_parse)
        if not valid_files:
            logging.error("No valid data files found for processing.")
            return

        load_data_from_files(valid_files)
        print(f"Data processing completed.")

    except Exception as e:
        logging.error(f"Error during data processing: {e}")

def load_data_from_files(files):
    """ Load data from a list of files and insert into the database. """
    for fIndex in files:
        try:
            data = parse_file(fIndex)
            if data:
                dbu.insert_data_into_malware_hashes(fIndex, data)
            else:
                logging.warning(f"No valid data parsed from {fIndex}.")
        except Exception as e:
            logging.error(f"Error in processing file {fIndex}: {e}")

def process_lines(lines, month_mapping, file_path):
    """ Process file lines and return structured malware data. """
    malware_data = []
    current_month = None
    malware_name = None

    for line_number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line: 
            continue  # Skip empty lines

        # month
        if line.startswith('**'):
            current_month = update_month(line, month_mapping, current_month)
            logging.debug(f'Updated month at line {line_number}: {current_month}')

        # malware name
        elif line.startswith('-'):
            malware_name = update_malware_name(line, malware_name)
            logging.debug(f'Updated malware id at line {line_number}: {malware_name}')

        elif malware_name:
            try:
                malware_entry = parse_malware_entry(line, malware_name, file_path, current_month)
                if malware_entry:
                    malware_data.append(malware_entry)
                    logging.debug(f'Malware entry added from line {line_number}: {malware_entry}')
            except ValueError as e:
                logging.error(f"Error at line {line_number} in file {file_path}: {e}")
                logging.error(f"Problematic data: '{line}'")

    if not malware_data:
        logging.warning(f'No valid malware data extracted from file: {file_path}')

    return malware_data

def parse_malware_entry(line, name, file_path, month):
    """ Parse a single line of malware data and return a structured entry. """
    # Extract the file name from the file path
    file_name = file_path.split('/')[-1]

    # Check if the file name matches the 'YYYY-README.txt' format and extract the year
    year_match = re.match(r'(\d{4})-README\.txt', file_name)
    year = year_match.group(1) if year_match else None

    # Assuming the hash strings don't have a specific prefix and are direct hash values.
    md5, sha1, sha256 = hash_utils.determine_hash_fields(line)
    if any([md5, sha1, sha256]):
        # Return the structured entry, including the year (or None if not found)
        return name, name, md5, sha1, sha256, file_path, month, year
    else:
        raise ValueError(f"Invalid hash string: '{line}'")

def generate_month_mapping():
    """ Generate a mapping from abbreviated to full month names. """
    return {month: calendar.month_name[i] for i, month in enumerate(calendar.month_abbr) if month}

def simplify_file_path(file_path):
    """ Simplify the file path for easier processing. """
    return file_path.replace('input/', '')

def update_month(line, month_mapping, current_month):
    """ Update and return the current month based on the line content. """
    if line.startswith('**'):
        month_str = line.strip('*').strip()
        return month_mapping.get(month_str, month_str)
    return current_month

def update_malware_name(line, name):
    """ Update and return the current malware name based on the line content. """
    if line.startswith('-'):
        return line.strip('-').strip()
    return name

def parse_file(file_path):
    """ Parse data from a given file and return structured malware data. """
    logging.info('Parsing file: ' + file_path)
    month_mapping = generate_month_mapping()
    simplified_file_path = simplify_file_path(file_path)

    try:
        lines = read_file_lines(file_path)
        return process_lines(lines, month_mapping, simplified_file_path)
    except Exception as e:
        logging.error(f'Error reading {file_path}: {e}')
        return []
