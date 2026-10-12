#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""Basit SQLite cache. TTL destekli."""

import hashlib
import json
import os
import sqlite3
import threading
import time

from core.config import CONFIG


_LOCK = threading.Lock()
_CONN = None


def _conn():
    global _CONN
    if _CONN is not None:
        return _CONN
    path = CONFIG["cache"]["path"]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache ("
        " key TEXT PRIMARY KEY, value TEXT, ts REAL )"
    )
    conn.commit()
    _CONN = conn
    return conn


def _key(namespace, payload):
    raw = namespace + "|" + json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def get(namespace, payload):
    if not CONFIG["cache"]["enabled"]:
        return None
    k = _key(namespace, payload)
    ttl = CONFIG["cache"]["ttl"]
    with _LOCK:
        row = _conn().execute(
            "SELECT value, ts FROM cache WHERE key=?", (k,)
        ).fetchone()
    if not row:
        return None
    value, ts = row
    if time.time() - ts > ttl:
        return None
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def set(namespace, payload, value):
    if not CONFIG["cache"]["enabled"]:
        return
    k = _key(namespace, payload)
    with _LOCK:
        _conn().execute(
            "INSERT OR REPLACE INTO cache(key, value, ts) VALUES (?,?,?)",
            (k, json.dumps(value, default=str), time.time()),
        )
        _conn().commit()


def clear():
    with _LOCK:
        _conn().execute("DELETE FROM cache")
        _conn().commit()