#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KaanDGN ARGUS

"""SQLite entity store — auto-migration destekli.

Şema değiştiğinde kendini otomatik migrate eder. Kullanıcı DB silmek
zorunda kalmaz.
"""

import json
import os
import sqlite3
import threading
import time


_LOCK = threading.Lock()
_CONN = None
_DB_PATH = "data/argus.sqlite"


def _ensure_relations_schema(conn):
    """relations tablosu UNIQUE constraint'siz ise migrate et."""
    try:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='relations'"
        ).fetchone()
        if row and "UNIQUE" not in row[0].upper():
            # Eski şema — migrate et, verileri koru
            conn.execute("ALTER TABLE relations RENAME TO relations_old")
            conn.execute("""CREATE TABLE relations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src TEXT, dst TEXT, kind TEXT, evidence TEXT, ts REAL,
                UNIQUE(src, dst, kind)
            )""")
            conn.execute("""INSERT OR IGNORE INTO relations(src, dst, kind, evidence, ts)
                SELECT src, dst, kind, MIN(evidence), MIN(ts) FROM relations_old
                GROUP BY src, dst, kind""")
            conn.execute("DROP TABLE relations_old")
            conn.commit()
    except sqlite3.Error:
        pass


def _ensure_entities_schema(conn):
    """entities tablosu UNIQUE constraint'siz ise migrate et."""
    try:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='entities'"
        ).fetchone()
        if row and "UNIQUE" not in row[0].upper():
            conn.execute("ALTER TABLE entities RENAME TO entities_old")
            conn.execute("""CREATE TABLE entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                etype TEXT NOT NULL,
                value TEXT NOT NULL,
                data TEXT,
                source TEXT,
                confidence TEXT,
                created REAL,
                UNIQUE(etype, value, source)
            )""")
            conn.execute("""INSERT OR IGNORE INTO entities(etype,value,data,source,confidence,created)
                SELECT etype, value, data, source, confidence, MIN(created)
                FROM entities_old GROUP BY etype, value, source""")
            conn.execute("DROP TABLE entities_old")
            conn.commit()
    except sqlite3.Error:
        pass


def _conn():
    global _CONN
    if _CONN is not None:
        return _CONN

    os.makedirs(os.path.dirname(_DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)

    conn.execute("""CREATE TABLE IF NOT EXISTS entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        etype TEXT NOT NULL,
        value TEXT NOT NULL,
        data TEXT,
        source TEXT,
        confidence TEXT,
        created REAL,
        UNIQUE(etype, value, source)
    )""")

    conn.execute("""CREATE TABLE IF NOT EXISTS relations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src TEXT, dst TEXT, kind TEXT, evidence TEXT, ts REAL,
        UNIQUE(src, dst, kind)
    )""")

    conn.execute("""CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE, note TEXT, created REAL
    )""")
    conn.commit()

    # Şema migration — eski tablolar varsa düzelt
    _ensure_relations_schema(conn)
    _ensure_entities_schema(conn)

    _CONN = conn
    return conn


def add_entity(etype, value, data=None, source=None, confidence=None):
    with _LOCK:
        try:
            _conn().execute(
                "INSERT OR IGNORE INTO entities"
                "(etype,value,data,source,confidence,created) "
                "VALUES (?,?,?,?,?,?)",
                (etype, value, json.dumps(data or {}, default=str),
                 source or "unknown", confidence or "UNKNOWN", time.time()),
            )
            _conn().commit()
        except sqlite3.Error:
            pass


def add_relation(src, dst, kind, evidence=None):
    with _LOCK:
        try:
            _conn().execute(
                "INSERT OR IGNORE INTO relations(src,dst,kind,evidence,ts) "
                "VALUES (?,?,?,?,?)",
                (src, dst, kind, evidence or "", time.time()),
            )
            _conn().commit()
        except sqlite3.Error:
            pass


def get_entities(etype=None, limit=200):
    q = "SELECT etype,value,data,source,confidence,created FROM entities"
    args = []
    if etype:
        q += " WHERE etype=?"
        args.append(etype)
    q += " ORDER BY created DESC LIMIT ?"
    args.append(limit)
    with _LOCK:
        return _conn().execute(q, args).fetchall()


def get_relations(limit=200):
    with _LOCK:
        return _conn().execute(
            "SELECT src,dst,kind,evidence,ts FROM relations ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()


def create_case(name, note=""):
    with _LOCK:
        try:
            _conn().execute(
                "INSERT INTO cases(name,note,created) VALUES (?,?,?)",
                (name, note, time.time()),
            )
            _conn().commit()
            return True
        except sqlite3.IntegrityError:
            return False


def list_cases():
    with _LOCK:
        return _conn().execute(
            "SELECT name,note,created FROM cases ORDER BY created DESC"
        ).fetchall()