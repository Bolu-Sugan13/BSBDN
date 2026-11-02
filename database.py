import sqlite3
import json
from contextlib import contextmanager

DB_PATH = "bsbdn.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_session():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


@contextmanager
def db_immediate_session(timeout=10.0):
    """
    Acquires an immediate exclusive lock transaction for concurrent-safe writes
    (such as blockchain block creation).
    """
    conn = sqlite3.connect(DB_PATH, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def init_db():
    with db_session() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('patient','doctor','admin')),
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS health_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual',
                heart_rate REAL,
                bp_sys REAL,
                bp_dia REAL,
                oxygen_level REAL,
                temperature REAL,
                notes TEXT,
                recorded_at TEXT DEFAULT (datetime('now')),
                block_id INTEGER,
                FOREIGN KEY (patient_id) REFERENCES users(id),
                FOREIGN KEY (block_id) REFERENCES blocks(id)
            );

            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idx INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                data TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            -- Phase 1: Unique index for concurrency-safe blocks
            CREATE UNIQUE INDEX IF NOT EXISTS idx_blocks_idx ON blocks(idx);

            -- Phase 1: Doctor-patient consent and authorization
            CREATE TABLE IF NOT EXISTS doctor_patient_consent (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                doctor_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'approved' CHECK(status IN ('pending', 'approved', 'revoked')),
                granted_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (patient_id) REFERENCES users(id),
                FOREIGN KEY (doctor_id) REFERENCES users(id),
                UNIQUE (patient_id, doctor_id)
            );

            -- Phase 1: Patient data access audit trail
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                viewer_id INTEGER NOT NULL,
                patient_id INTEGER NOT NULL,
                access_type TEXT NOT NULL,
                ip_address TEXT,
                viewed_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (viewer_id) REFERENCES users(id),
                FOREIGN KEY (patient_id) REFERENCES users(id)
            );
            """
        )

        # Check if users table needs 'status' column
        user_cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "status" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")



def log_activity(user_id, action, details=""):
    with db_session() as conn:
        conn.execute(
            "INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)",
            (user_id, action, details),
        )


def organ_status_from_vitals(hr, bp_sys, bp_dia, spo2, temp):
    """
    Simple rule-based mapping from vitals to organ health status.
    Returns dict: organ -> 'green' | 'yellow' | 'red'
    """
    def bucket(value, green_range, yellow_range):
        if value is None:
            return "yellow"
        lo, hi = green_range
        if lo <= value <= hi:
            return "green"
        ylo, yhi = yellow_range
        if ylo <= value <= yhi:
            return "yellow"
        return "red"

    heart = bucket(hr, (60, 100), (50, 120))
    lungs = bucket(spo2, (95, 100), (90, 95))
    # Kidneys/liver proxied loosely off BP + temperature for this simulation
    kidneys = bucket(bp_sys, (90, 129), (80, 139)) if bp_sys is not None else "yellow"
    liver = bucket(temp, (36.1, 37.5), (35.5, 38.5)) if temp is not None else "yellow"
    brain = bucket(bp_dia, (60, 89), (50, 99)) if bp_dia is not None else "yellow"

    return {
        "heart": heart,
        "lungs": lungs,
        "kidneys": kidneys,
        "liver": liver,
        "brain": brain,
    }


def overall_status(organ_map):
    if "red" in organ_map.values():
        return "red"
    if "yellow" in organ_map.values():
        return "yellow"
    return "green"
