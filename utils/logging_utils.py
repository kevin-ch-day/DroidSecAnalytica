# logging_utils.py

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

logger_initialized = False

DEFAULT_LOG_LEVEL = logging.INFO  # Default logging level


def setup_logger(
    level: Optional[int] = DEFAULT_LOG_LEVEL,
    log_file: Optional[str] = None,
    max_log_size: int = 10485760,
    backup_count: int = 3,
):
    """Configure the root application logger once."""
    global logger_initialized
    if logger_initialized:
        return
    logger_initialized = True

    if isinstance(level, str):
        level = getattr(logging, level.upper(), DEFAULT_LOG_LEVEL)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(level)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_log_size, backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


def get_logger(
    name: Optional[str] = None,
    log_file: Optional[str] = None,
    max_log_size: int = 10485760,
    backup_count: int = 3,
) -> logging.Logger:
    """Return a module-specific logger and attach a file handler if requested."""
    logger = logging.getLogger(name)

    if log_file:
        log_file = os.path.abspath(log_file)
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handler_exists = any(
            isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", "") == log_file
            for h in logger.handlers
        )
        if not handler_exists:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler = RotatingFileHandler(
                log_file, maxBytes=max_log_size, backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger
