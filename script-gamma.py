import os
import sys
import logging

# Import custom libraries
from virustotal import vt_analysis
from reporting import *
from utils import logging_utils
from database import *

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure Logging using logging_utils
logging_utils.setup_logger(level=logging.INFO, log_file='logs/main.log')


def main():
    try:
        #vt_analysis.run_analysis()
        vt_analysis.run_hash_ioc()
    except Exception as e:
        logging_utils.log_critical(f"An error occurred: {e}", exc_info=True)
        print("An error occurred. Please check the logs for more details.")

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        logging_utils.log_info("Program interrupted by the user. Exiting...")
        print("\nProgram interrupted by the user. Exiting...")

    except Exception as e:
        logging_utils.log_critical(f"Critical error on startup: {e}", exc_info=True)
        print("A critical error occurred on startup. Please check the logs for more details.")
        sys.exit(1)