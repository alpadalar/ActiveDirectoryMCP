"""Logging configuration for Active Directory MCP."""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

from ..config.models import LoggingConfig
from ..redaction import RedactingFilter, install_record_factory


def setup_logging(config: LoggingConfig) -> logging.Logger:
    """
    Setup logging configuration.

    Args:
        config: Logging configuration

    Returns:
        Logger instance
    """
    # Redact at record creation so no logger or handler can bypass the filter
    install_record_factory()

    # Create logger
    logger = logging.getLogger("active-directory-mcp")
    logger.setLevel(getattr(logging, config.level))

    # Clear existing handlers
    logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(config.format)

    # Console handler - use stderr to avoid interfering with MCP stdio protocol
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(getattr(logging, config.level))
    console_handler.setFormatter(formatter)
    console_handler.addFilter(RedactingFilter())
    logger.addHandler(console_handler)

    # File handler (if specified)
    if config.file:
        try:
            # Ensure log directory exists
            log_file = Path(config.file)
            log_file.parent.mkdir(parents=True, exist_ok=True)

            # Create rotating file handler (10MB max, keep 5 files)
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setLevel(getattr(logging, config.level))
            file_handler.setFormatter(formatter)
            file_handler.addFilter(RedactingFilter())
            logger.addHandler(file_handler)

            logger.info(f"Logging to file: {config.file}")

        except Exception as e:
            logger.warning(f"Could not setup file logging: {e}")

    # Suppress some noisy loggers
    logging.getLogger("ldap3").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    logger.info(f"Logging initialized at level: {config.level}")
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(f"active-directory-mcp.{name}")


def log_ldap_operation(
    operation: str, dn: str, success: bool, details: Optional[str] = None
) -> None:
    """
    Log LDAP operation for audit purposes.

    Args:
        operation: Operation type (search, add, modify, delete, etc.)
        dn: Distinguished name involved
        success: Whether operation was successful
        details: Additional details
    """
    logger = get_logger("audit")

    status = "SUCCESS" if success else "FAILED"
    message = f"LDAP {operation.upper()} {status}: {dn}"

    if details:
        message += f" - {details}"

    if success:
        logger.info(message)
    else:
        logger.warning(message)
