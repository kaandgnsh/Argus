#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

import json
import os


_DEFAULT = {
    "app": {
        "name": "ARGUS",
        "version": "0.1.0",
        "timeout": 8,
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/119.0.0.0 Safari/537.36"
        ),
    },
    "search": {
        "max_results": 10,
        "providers": ["duckduckgo"],
    },
    "http": {"retries": 2, "backoff": 1.5, "verify_tls": True},
    "proxy": {
        "enabled": False, "http": "", "https": "", "socks5": "",
        "tor": False, "tor_socks5": "socks5h://127.0.0.1:9050",
    },
    "cache": {"enabled": True, "ttl": 3600, "path": "cache/argus.sqlite"},
    "logging": {"level": "INFO", "dir": "logs"},
}


def _deep_merge(base, override):
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path="config/config.json"):
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(_DEFAULT, f, indent=4, ensure_ascii=False)
        return dict(_DEFAULT)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return _deep_merge(_DEFAULT, json.load(f))
    except (OSError, json.JSONDecodeError):
        return dict(_DEFAULT)


CONFIG = load()