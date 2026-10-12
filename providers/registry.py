#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Basit provider registry — config/providers.json'dan enable/disable."""

import json
import os


_REGISTRY = {}


def register(cls):
    _REGISTRY[cls.name] = cls
    return cls


def _load_conf(path="config/providers.json"):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def get(name):
    cls = _REGISTRY.get(name)
    if cls is None:
        return None
    opts = _load_conf().get(name, {})
    return cls(**opts)


def all_providers():
    conf = _load_conf()
    out = []
    for name, cls in _REGISTRY.items():
        opts = conf.get(name, {})
        out.append(cls(**opts))
    return out


def enabled_providers():
    return [p for p in all_providers() if getattr(p, "enabled", True)]