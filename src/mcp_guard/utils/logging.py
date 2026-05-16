"""Tiny logging helper that respects --debug without dragging in Rich's
log handler everywhere."""

from __future__ import annotations

import logging
import os
import sys
from typing import Final

_LOGGER_NAME: Final = "mcp_guard"


def configure(debug: bool = False) -> None:
    level = logging.DEBUG if debug or os.environ.get("MCP_GUARD_DEBUG") else logging.WARNING
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)
    if logger.handlers:
        for h in logger.handlers:
            h.setLevel(level)
        return
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s mcp-guard] %(message)s"))
    handler.setLevel(level)
    logger.addHandler(handler)


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)
