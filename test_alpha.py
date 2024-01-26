import sys

from virustotal import vt_analysis
from utils import logging_utils

if __name__ == "__main__":
    try:
        vt_analysis.virustotal_menu()

    except KeyboardInterrupt:
        logging_utils.log_info("Program interrupted by the user. Exiting...")
        print("\nProgram interrupted by the user. Exiting...")

    except Exception as e:
        logging_utils.log_critical(f"Critical error on startup: {e}", exc_info=True)
        print("A critical error occurred on startup. Please check the logs for more details.")
        sys.exit(1)