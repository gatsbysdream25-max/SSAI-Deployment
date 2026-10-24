#!/usr/bin/env python3
"""
One-shot migration: add provider_health to Agent table.
Run once: python3 migrate_provider_health.py
Safe to run multiple times — skips columns that already exist.
"""
import sqlite3
import os

import ssai_config

DB_PATH = os.environ.get('SSAI_DB', ssai_config.DB_PATH)

MIGRATIONS = [
    "ALTER TABLE agent ADD COLUMN provider_health TEXT",
]

def column_exists(conn, table, column):
    cur = conn.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())

def run():
    """Add the provider_health column to the agent table if it is not there yet, so the script is safe to run twice."""
    if not os.path.exists(DB_PATH):
        print(f"DB not found at {DB_PATH} — check SSAI_DB env var")
        return
    conn = sqlite3.connect(DB_PATH)
    try:
        for stmt in MIGRATIONS:
            col = stmt.split('ADD COLUMN')[1].strip().split()[0]
            if column_exists(conn, 'agent', col):
                print(f"  skip  — column '{col}' already exists")
            else:
                conn.execute(stmt)
                conn.commit()
                print(f"  added — column '{col}'")
        print("Migration complete.")
    finally:
        conn.close()

if __name__ == '__main__':
    run()
