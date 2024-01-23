# logging_utils.py

import logging
from typing import Optional

# Initialize logger
logger = logging.getLogger(__name__)

def setup_logger(level=logging.INFO, log_file=None):
    """
    Set up the logger with specified level and optional log file.
    """
    logger.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

def log_warning(message: str):
    logger.warning(message)

def log_error(message: str, error: Optional[Exception] = None):
    if error:
        logger.error(f"{message}: {error}")
    else:
        logger.error(message)

def log_info(message: str):
    logger.info(message)

