# logging_utils.py

import logging
from logging.handlers import RotatingFileHandler
import traceback
from typing import Optional

# Initialize logger
logger = logging.getLogger(__name__)
logger_initialized = False

DEFAULT_LOG_LEVEL = logging.INFO  # Default logging level

def setup_logger(level: Optional[int] = DEFAULT_LOG_LEVEL, log_file: Optional[str] = None, max_log_size: int = 10485760, backup_count: int = 3):
    global logger_initialized
    if logger_initialized:
        return
    logger_initialized = True

    if isinstance(level, str):
        level = getattr(logging, level.upper(), DEFAULT_LOG_LEVEL)
    logger.setLevel(level)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if log_file:
        fh = RotatingFileHandler(log_file, maxBytes=max_log_size, backupCount=backup_count)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

def log_warning(message: str):
    try:
        logger.warning(message)
    except Exception as e:
        print(f"Error logging warning: {e}\n{traceback.format_exc()}")

def log_error(message: str, error: Optional[Exception] = None):
    try:
        log_message = f"{message}: {error}" if error else message
        logger.error(log_message)
    except Exception as e:
        print(f"Error logging error: {e}\n{traceback.format_exc()}")

def log_info(message: str):
    try:
        logger.info(message)
    except Exception as e:
        print(f"Error logging info: {e}\n{traceback.format_exc()}")

def log_debug(message: str):
    try:
        logger.debug(message)
    except Exception as e:
        print(f"Error logging debug: {e}\n{traceback.format_exc()}")

def log_critical(message: str):
    try:
        logger.critical(message)
    except Exception as e:
        print(f"Error logging critical: {e}\n{traceback.format_exc()}")
