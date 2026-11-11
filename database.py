import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "phishshield.db"


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                ml_score INTEGER NOT NULL,
                rule_score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)
        conn.commit()


def save_scan(result: dict):
    timestamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    with _connect() as conn:
        cursor = conn.execute("""
            INSERT INTO scans
            (url, verdict, level, risk_score, ml_score, rule_score, reasons, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result["url"], result["verdict"], result["level"],
            result["risk_score"], result["ml_score"], result["rule_score"],
            json.dumps(result["reasons"]), timestamp
        ))
        conn.commit()
        return cursor.lastrowid


def get_history(limit: int = 12):
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["reasons"] = json.loads(item["reasons"])
        output.append(item)
    return output


def get_stats():
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM scans WHERE level = 'high'").fetchone()[0]
        medium = conn.execute("SELECT COUNT(*) FROM scans WHERE level = 'medium'").fetchone()[0]
    return {"total": total, "high_risk": high, "suspicious": medium}


def clear_history():
    with _connect() as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()
