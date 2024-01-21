# load_data.py

import logging
import os

from database import DBUtils as dbu

def read_file_lines(file_path):
    """ Read and return all lines from the file. """
    with open(file_path, 'r') as file:
        return file.readlines()

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