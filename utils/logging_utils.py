# logging_utils.py

import logging
from logging.handlers import RotatingFileHandler
import os
from typing import Optional

# Initialize logger
logger = logging.getLogger(__name__)
logger_initialized = False

def setup_logger(level: Optional[int] = None, log_file: Optional[str] = None, max_log_size: int = 10485760, backup_count: int = 3):
    # Set up the logger with specified level, optional log file, and log rotation
    global logger_initialized
    if logger_initialized:
        return
    logger_initialized = True

    level = level or os.getenv("LOG_LEVEL", logging.INFO)
    logger.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Console handler
    if not any(isinstance(handler, logging.StreamHandler) for handler in logger.handlers):
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    # Rotating file handler
    if log_file:
        fh = RotatingFileHandler(log_file, maxBytes=max_log_size, backupCount=backup_count)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

def log_warning(message: str):
    # Log a warning message
    try:
        logger.warning(message)
    except Exception as e:
        print(f"Logging Warning failed: {e}")

def log_error(message: str, error: Optional[Exception] = None):
    # Log an error message
    try:
        log_message = f"{message}: {error}" if error else message
        logger.error(log_message)
    except Exception as e:
        print(f"Logging Error failed: {e}")

def log_info(message: str):
    # Log an info message
    try:
        logger.info(message)
    except Exception as e:
        print(f"Logging Info failed: {e}")

def log_debug(message: str):
    # Log a debug message
    try:
        logger.debug(message)
    except Exception as e:
        print(f"Logging Debug failed: {e}")
