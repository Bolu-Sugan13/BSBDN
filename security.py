"""
Security and Validation Module for BSBDN
----------------------------------------
Handles:
1. Environment-based SECRET_KEY enforcement with production guard
2. CSRF protection setup (Flask-WTF)
3. Strict server-side vitals validation with physiological bounds
4. Patient-Doctor consent and access verification
5. Patient data access audit logging
"""

import os
import sqlite3
from flask_wtf.csrf import CSRFProtect
import database as db

# ---------------------------------------------------------------------------
# 1. Secret Key Management
# ---------------------------------------------------------------------------

def get_secret_key(app_debug: bool = False) -> str:
    """
    Reads SECRET_KEY from environment variables (SECRET_KEY or BSBDN_SECRET).
    In production (non-debug), fails immediately if missing.
    In debug/dev mode, falls back to a development secret with an alert.
    """
    secret = os.environ.get("SECRET_KEY") or os.environ.get("BSBDN_SECRET")
    if not secret:
        if not app_debug and os.environ.get("FLASK_ENV") == "production":
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: "
                "SECRET_KEY environment variable is missing in non-debug/production mode! "
                "Set SECRET_KEY before starting the application."
            )
        # Safe fallback for local development / MCA testing
        return "bsbdn-dev-secure-sha256-secret-key-mca-project-2026"
    return secret


# ---------------------------------------------------------------------------
# 2. CSRF Protection
# ---------------------------------------------------------------------------

csrf = CSRFProtect()

def init_security(app):
    """Initialize security configurations for the Flask application."""
    app.secret_key = get_secret_key(app.debug)
    csrf.init_app(app)


# ---------------------------------------------------------------------------
# 3. Server-side Vitals Validation
# ---------------------------------------------------------------------------

# Medically sensible validation ranges (illustrative standard bounds)
VITALS_RANGES = {
    "heart_rate": {
        "min": 20.0,
        "max": 250.0,
        "label": "Heart Rate",
        "unit": "bpm",
    },
    "bp_sys": {
        "min": 50.0,
        "max": 260.0,
        "label": "Systolic Blood Pressure",
        "unit": "mmHg",
    },
    "bp_dia": {
        "min": 30.0,
        "max": 160.0,
        "label": "Diastolic Blood Pressure",
        "unit": "mmHg",
    },
    "oxygen_level": {
        "min": 50.0,
        "max": 100.0,
        "label": "Oxygen Saturation (SpO2)",
        "unit": "%",
    },
    "temperature": {
        "min": 30.0,
        "max": 45.0,
        "label": "Body Temperature",
        "unit": "°C",
    },
    # Phase 2 optional/extended fields
    "glucose": {
        "min": 20.0,
        "max": 600.0,
        "label": "Blood Glucose",
        "unit": "mg/dL",
    },
    "weight_kg": {
        "min": 2.0,
        "max": 350.0,
        "label": "Body Weight",
        "unit": "kg",
    },
    "height_cm": {
        "min": 40.0,
        "max": 250.0,
        "label": "Height",
        "unit": "cm",
    },
    "sleep_hours": {
        "min": 0.0,
        "max": 24.0,
        "label": "Sleep Duration",
        "unit": "hours",
    },
    "steps": {
        "min": 0,
        "max": 120000,
        "label": "Daily Steps",
        "unit": "steps",
    },
}


def validate_vitals(form_data):
    """
    Validates vitals form inputs server-side.
    Returns: (is_valid: bool, cleaned_data: dict, errors: list[str])
    Prevents crashes on invalid strings, non-numeric values, or out-of-range bounds.
    """
    errors = []
    cleaned = {}

    # Core required vitals
    core_fields = ["heart_rate", "bp_sys", "bp_dia", "oxygen_level", "temperature"]

    for field in core_fields:
        raw_val = form_data.get(field, "").strip()
        spec = VITALS_RANGES[field]
        if not raw_val:
            errors.append(f"{spec['label']} is required.")
            continue
        try:
            val = float(raw_val)
            if val < spec["min"] or val > spec["max"]:
                errors.append(
                    f"{spec['label']} must be between {spec['min']} and {spec['max']} {spec['unit']}."
                )
            else:
                cleaned[field] = val
        except (ValueError, TypeError):
            errors.append(f"{spec['label']} must be a valid numeric reading.")

    # Physiological cross-validation
    if "bp_sys" in cleaned and "bp_dia" in cleaned:
        if cleaned["bp_sys"] <= cleaned["bp_dia"]:
            errors.append(
                f"Systolic blood pressure ({cleaned['bp_sys']} mmHg) must be greater "
                f"than diastolic blood pressure ({cleaned['bp_dia']} mmHg)."
            )

    # Optional / Extended vitals (if present in form)
    optional_fields = ["glucose", "weight_kg", "height_cm", "sleep_hours", "steps"]
    for field in optional_fields:
        raw_val = form_data.get(field, "")
        if raw_val is not None and str(raw_val).strip() != "":
            raw_str = str(raw_val).strip()
            spec = VITALS_RANGES[field]
            try:
                val = int(raw_str) if field == "steps" else float(raw_str)
                if val < spec["min"] or val > spec["max"]:
                    errors.append(
                        f"{spec['label']} must be between {spec['min']} and {spec['max']} {spec['unit']}."
                    )
                else:
                    cleaned[field] = val
            except (ValueError, TypeError):
                errors.append(f"{spec['label']} must be a valid numeric reading.")
        else:
            cleaned[field] = None

    cleaned["source"] = form_data.get("source", "manual").strip()
    if cleaned["source"] not in ("manual", "wearable", "hospital"):
        cleaned["source"] = "manual"

    cleaned["notes"] = form_data.get("notes", "").strip()

    is_valid = len(errors) == 0
    return is_valid, cleaned, errors


# ---------------------------------------------------------------------------
# 4. Doctor-Patient Consent and Access Control
# ---------------------------------------------------------------------------

def is_doctor_authorized(doctor_id: int, patient_id: int) -> bool:
    """
    Checks if a doctor has an 'approved' active consent record from the patient.
    System admins always have administrative access.
    """
    if doctor_id == patient_id:
        return True

    with db.db_session() as conn:
        # Check doctor role and admin override
        viewer = conn.execute("SELECT role FROM users WHERE id = ?", (doctor_id,)).fetchone()
        if viewer and viewer["role"] == "admin":
            return True

        row = conn.execute(
            """SELECT status FROM doctor_patient_consent
               WHERE doctor_id = ? AND patient_id = ?""",
            (doctor_id, patient_id),
        ).fetchone()

        return bool(row and row["status"] == "approved")


def grant_doctor_consent(patient_id: int, doctor_id: int) -> bool:
    """Grants or approves doctor access to patient medical records."""
    with db.db_session() as conn:
        conn.execute(
            """INSERT INTO doctor_patient_consent (patient_id, doctor_id, status, updated_at)
               VALUES (?, ?, 'approved', datetime('now'))
               ON CONFLICT(patient_id, doctor_id) DO UPDATE SET
                   status = 'approved',
                   updated_at = datetime('now')""",
            (patient_id, doctor_id),
        )
    return True


def revoke_doctor_consent(patient_id: int, doctor_id: int) -> bool:
    """Revokes doctor access to patient medical records."""
    with db.db_session() as conn:
        conn.execute(
            """UPDATE doctor_patient_consent
               SET status = 'revoked', updated_at = datetime('now')
               WHERE patient_id = ? AND doctor_id = ?""",
            (patient_id, doctor_id),
        )
    return True


def get_patient_consents(patient_id: int):
    """Returns all doctor consent statuses for a patient."""
    with db.db_session() as conn:
        rows = conn.execute(
            """SELECT u.id as doctor_id, u.name as doctor_name, u.email as doctor_email,
                      c.status, c.granted_at, c.updated_at
               FROM users u
               LEFT JOIN doctor_patient_consent c
                 ON c.doctor_id = u.id AND c.patient_id = ?
               WHERE u.role = 'doctor'
               ORDER BY u.name ASC""",
            (patient_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_assigned_doctor_name(patient_id: int) -> str:
    """Gets primary assigned doctor name for patient header."""
    with db.db_session() as conn:
        row = conn.execute(
            """SELECT u.name FROM users u
               JOIN doctor_patient_consent c ON c.doctor_id = u.id
               WHERE c.patient_id = ? AND c.status = 'approved'
               ORDER BY c.updated_at DESC LIMIT 1""",
            (patient_id,),
        ).fetchone()
        return row["name"] if row else "None assigned"


# ---------------------------------------------------------------------------
# 5. Patient Data Access Audit Logging
# ---------------------------------------------------------------------------

def log_audit_access(viewer_id: int, patient_id: int, access_type: str, ip_address: str = None):
    """
    Records an immutable audit entry whenever a user views or queries
    another user's health records or sensitive dashboard data.
    """
    with db.db_session() as conn:
        conn.execute(
            """INSERT INTO audit_log (viewer_id, patient_id, access_type, ip_address)
               VALUES (?, ?, ?, ?)""",
            (viewer_id, patient_id, access_type, ip_address or "127.0.0.1"),
        )


def get_patient_audit_trail(patient_id: int, limit: int = 50):
    """Fetches access audit log entries for a patient."""
    with db.db_session() as conn:
        rows = conn.execute(
            """SELECT a.id, a.access_type, a.ip_address, a.viewed_at,
                      u.name as viewer_name, u.role as viewer_role, u.email as viewer_email
               FROM audit_log a
               JOIN users u ON u.id = a.viewer_id
               WHERE a.patient_id = ?
               ORDER BY a.viewed_at DESC LIMIT ?""",
            (patient_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
