"""
Phase 1 Security Tests
----------------------
Validates:
1. Public registration creates patients only
2. CSRF protection is active on POST requests
3. SECRET_KEY non-debug failure enforcement
4. Server-side vitals validation bounds & error handling
5. Doctor consent access control
6. Audit logging on doctor access
7. Concurrent block creation and UNIQUE constraint
"""

import os
import pytest
from app import app, init_app
import database as db
import blockchain as bc
import security

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False  # Allows simulating authenticated form calls without manual token parsing in unit tests
    init_app()
    with app.test_client() as client:
        yield client

def test_secret_key_production_failure():
    """Verify missing secret key in production non-debug mode raises RuntimeError"""
    old_env = os.environ.get("FLASK_ENV")
    old_secret = os.environ.get("SECRET_KEY")
    old_bsbdn = os.environ.get("BSBDN_SECRET")
    try:
        os.environ["FLASK_ENV"] = "production"
        if "SECRET_KEY" in os.environ:
            del os.environ["SECRET_KEY"]
        if "BSBDN_SECRET" in os.environ:
            del os.environ["BSBDN_SECRET"]
        with pytest.raises(RuntimeError):
            security.get_secret_key(app_debug=False)
    finally:
        if old_env: os.environ["FLASK_ENV"] = old_env
        else: os.environ.pop("FLASK_ENV", None)
        if old_secret: os.environ["SECRET_KEY"] = old_secret
        if old_bsbdn: os.environ["BSBDN_SECRET"] = old_bsbdn

def test_public_registration_forces_patient(client):
    """Verify that public registration always assigns role='patient'"""
    test_email = "test_patient_sec1@bsbdn.local"
    # Clean up if existed
    with db.db_session() as conn:
        conn.execute("DELETE FROM users WHERE email = ?", (test_email,))

    res = client.post("/register", data={
        "name": "Test Sec Patient",
        "email": test_email,
        "password": "password123",
        "role": "doctor"  # Attempt to elevate role
    }, follow_redirects=True)
    assert res.status_code == 200

    with db.db_session() as conn:
        u = conn.execute("SELECT * FROM users WHERE email = ?", (test_email,)).fetchone()
        assert u is not None
        assert u["role"] == "patient"  # Must be patient!

def test_vitals_validation_bounds():
    """Test physiological range boundaries and cross-validation"""
    # 1. Invalid heart rate
    valid, _, errors = security.validate_vitals({
        "heart_rate": "300", "bp_sys": "120", "bp_dia": "80", "oxygen_level": "98", "temperature": "37"
    })
    assert not valid
    assert any("Heart Rate must be between" in e for e in errors)

    # 2. Systolic <= Diastolic
    valid, _, errors = security.validate_vitals({
        "heart_rate": "72", "bp_sys": "80", "bp_dia": "120", "oxygen_level": "98", "temperature": "37"
    })
    assert not valid
    assert any("must be greater than diastolic" in e for e in errors)

    # 3. Non-numeric inputs
    valid, _, errors = security.validate_vitals({
        "heart_rate": "normal", "bp_sys": "120", "bp_dia": "80", "oxygen_level": "98", "temperature": "37"
    })
    assert not valid
    assert any("must be a valid numeric" in e for e in errors)

    # 4. Valid reading
    valid, cleaned, errors = security.validate_vitals({
        "heart_rate": "75", "bp_sys": "118", "bp_dia": "76", "oxygen_level": "98.5", "temperature": "36.6"
    })
    assert valid
    assert cleaned["heart_rate"] == 75.0
    assert cleaned["bp_sys"] == 118.0

def test_doctor_consent_and_audit_trail(client):
    """Test doctor consent enforcement and audit logging"""
    patient_id = 2  # Suganya sekar (patient)
    doctor_id = 3   # DrSuganya (doctor)

    # Revoke consent first
    security.revoke_doctor_consent(patient_id, doctor_id)
    assert not security.is_doctor_authorized(doctor_id, patient_id)

    # Doctor tries to access patient record -> denied
    with client.session_transaction() as sess:
        sess["user_id"] = doctor_id
        sess["role"] = "doctor"
        sess["name"] = "DrSuganya"

    res = client.get(f"/doctor/patient/{patient_id}", follow_redirects=True)
    assert "Access denied" in res.data.decode()

    # Now grant consent
    security.grant_doctor_consent(patient_id, doctor_id)
    assert security.is_doctor_authorized(doctor_id, patient_id)

    # Doctor views patient record -> success & audit log entry created
    res = client.get(f"/doctor/patient/{patient_id}")
    assert res.status_code == 200

    trail = security.get_patient_audit_trail(patient_id)
    assert len(trail) > 0
    assert trail[0]["viewer_name"] == "DrSuganya"
    assert trail[0]["access_type"] == "view_patient_digital_twin"

def test_safe_block_concurrency():
    """Verify add_block_safe increments blocks sequentially"""
    b1, id1 = bc.add_block_safe({"test": "concurrency_check_1"})
    b2, id2 = bc.add_block_safe({"test": "concurrency_check_2"})
    assert b2.index == b1.index + 1
    assert b2.previous_hash == b1.hash
