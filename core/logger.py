#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

import logging
import os
from logging.handlers import RotatingFileHandler

from core.config import CONFIG


_LOGGER = None


def get_logger(name="ARGUS"):
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER

    log_dir = CONFIG["logging"]["dir"]
    os.makedirs(log_dir, exist_ok=True)

    level = getattr(logging, CONFIG["logging"].get("level", "INFO").upper(), logging.INFO)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        fmt = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        fh = RotatingFileHandler(
            os.path.join(log_dir, "argus.log"),
            maxBytes=2_000_000, backupCount=3, encoding="utf-8",
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    _LOGGER = logger
    return logger