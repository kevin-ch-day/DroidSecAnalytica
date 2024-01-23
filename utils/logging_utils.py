import logging
from typing import Optional

def log_warning(message: str):
    logging.warning(message)

def log_error(message: str, error: Optional[Exception] = None):
    if error:
        logging.error(f"{message}: {error}")
    else:
        logging.error(message)

def log_info(message: str):
    logging.info(message)