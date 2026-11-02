import json
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import database as db
import blockchain as bc
import security
app = Flask(__name__)
# Phase 1: Environment-driven SECRET_KEY enforcement & Flask-WTF CSRF protection
security.init_security(app)
# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------
def ensure_genesis_block():
    with db.db_session() as conn:
        row = conn.execute("SELECT COUNT(*) c FROM blocks").fetchone()
        if row["c"] == 0:
            g = bc.genesis_block()
            conn.execute(
                "INSERT INTO blocks (idx, timestamp, data, previous_hash, hash) VALUES (?, ?, ?, ?, ?)",
                (g.index, g.timestamp, json.dumps(g.data), g.previous_hash, g.hash),
            )
def init_app():
    db.init_db()
    ensure_genesis_block()
# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            if role and session.get("role") != role and session.get("role") != "admin":
                flash("You don't have access to that page.", "error")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapped
    return decorator
def current_user():
    if "user_id" not in session:
        return None
    with db.db_session() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

# ---------------------------------------------------------------------------
# Public / Auth routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        # Phase 1: Public registration strictly creates patients only
        role = "patient"

        with db.db_session() as conn:
            existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                flash("An account with that email already exists.", "error")
                return redirect(url_for("register"))

            conn.execute(
                "INSERT INTO users (name, email, password_hash, role, status) VALUES (?, ?, ?, ?, 'active')",
                (name, email, generate_password_hash(password), role),
            )
        flash("Patient account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        with db.db_session() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            # Phase 1: Verify doctor account approval status
            user_status = user["status"] if "status" in user.keys() and user["status"] else "active"
            if user["role"] == "doctor" and user_status != "active":
                flash("Your doctor account is currently pending administrator approval or inactive.", "error")
                return redirect(url_for("login"))

            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["name"] = user["name"]
            db.log_activity(user["id"], "login")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")



@app.route("/logout")
def logout():
    if "user_id" in session:
        db.log_activity(session["user_id"], "logout")
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Patient: Digital Twin Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required()
def dashboard():
    user = current_user()
    if user["role"] == "doctor":
        return redirect(url_for("doctor_home"))
    if user["role"] == "admin":
        return redirect(url_for("admin_home"))

    with db.db_session() as conn:
        latest = conn.execute(
            "SELECT * FROM health_records WHERE patient_id = ? ORDER BY recorded_at DESC LIMIT 1",
            (user["id"],),
        ).fetchone()
        record_count = conn.execute(
            "SELECT COUNT(*) c FROM health_records WHERE patient_id = ?", (user["id"],)
        ).fetchone()["c"]

    organs = None
    overall = None
    if latest:
        organs = db.organ_status_from_vitals(
            latest["heart_rate"], latest["bp_sys"], latest["bp_dia"],
            latest["oxygen_level"], latest["temperature"],
        )
        overall = db.overall_status(organs)

    return render_template(
        "dashboard.html", user=user, latest=latest, organs=organs,
        overall=overall, record_count=record_count,
    )


@app.route("/add-record", methods=["GET", "POST"])
@login_required()
def add_record():
    user = current_user()
    if user["role"] != "patient":
        flash("Only patients can add their own vitals here.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # Phase 1: Server-side validation with sensible medical ranges
        is_valid, cleaned, errors = security.validate_vitals(request.form)
        if not is_valid:
            for err in errors:
                flash(err, "error")
            return render_template("add_record.html", form_data=request.form)

        # 1. Chain a new block for this record safely against concurrency
        block_data = {
            "patient_id": user["id"],
            "record_type": "vitals_update",
            "heart_rate": cleaned["heart_rate"],
            "bp_sys": cleaned["bp_sys"],
            "bp_dia": cleaned["bp_dia"],
            "oxygen_level": cleaned["oxygen_level"],
            "temperature": cleaned["temperature"],
            "source": cleaned["source"],
        }
        _, block_id = bc.add_block_safe(block_data)

        # 2. Store the health record, linked to its block
        with db.db_session() as conn:
            conn.execute(
                """INSERT INTO health_records
                   (patient_id, source, heart_rate, bp_sys, bp_dia, oxygen_level, temperature, notes, block_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user["id"], cleaned["source"], cleaned["heart_rate"], cleaned["bp_sys"],
                 cleaned["bp_dia"], cleaned["oxygen_level"], cleaned["temperature"],
                 cleaned["notes"], block_id),
            )

        db.log_activity(user["id"], "add_record", f"hr={cleaned['heart_rate']} spo2={cleaned['oxygen_level']}")
        flash("Vitals verified, recorded, and committed to the blockchain.", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_record.html", form_data=None)



# ---------------------------------------------------------------------------
# Analytics + Prediction (shared API used by charts)
# ---------------------------------------------------------------------------

def _vitals_series(patient_id):
    with db.db_session() as conn:
        rows = conn.execute(
            "SELECT * FROM health_records WHERE patient_id = ? ORDER BY recorded_at ASC",
            (patient_id,),
        ).fetchall()
    return rows


def _predict_next(values, steps=5):
    """Simple linear trend projection using least-squares fit over the index."""
    n = len(values)
    if n < 2:
        return [values[-1]] * steps if values else []
    xs = list(range(n))
    mean_x = sum(xs) / n
    mean_y = sum(values) / n
    num = sum((xs[i] - mean_x) * (values[i] - mean_y) for i in range(n))
    den = sum((xs[i] - mean_x) ** 2 for i in range(n)) or 1
    slope = num / den
    intercept = mean_y - slope * mean_x
    return [round(intercept + slope * (n + i), 1) for i in range(steps)]


@app.route("/api/vitals/<int:patient_id>")
@login_required()
def api_vitals(patient_id):
    user = current_user()
    if user["role"] == "patient" and user["id"] != patient_id:
        return jsonify({"error": "forbidden"}), 403
    if user["role"] == "doctor":
        if not security.is_doctor_authorized(user["id"], patient_id):
            return jsonify({"error": "forbidden: doctor access not consented"}), 403
        security.log_audit_access(user["id"], patient_id, "api_vitals_query", request.remote_addr)

    rows = _vitals_series(patient_id)
    labels = [r["recorded_at"] for r in rows]
    hr = [r["heart_rate"] for r in rows]
    sys_ = [r["bp_sys"] for r in rows]
    dia = [r["bp_dia"] for r in rows]
    spo2 = [r["oxygen_level"] for r in rows]

    pred_steps = 5
    pred_labels = [f"+{i+1}" for i in range(pred_steps)]

    return jsonify({
        "labels": labels,
        "heart_rate": hr,
        "bp_sys": sys_,
        "bp_dia": dia,
        "oxygen_level": spo2,
        "prediction": {
            "labels": pred_labels,
            "heart_rate": _predict_next(hr, pred_steps),
            "oxygen_level": _predict_next(spo2, pred_steps),
        },
    })


@app.route("/analytics")
@app.route("/analytics/<int:patient_id>")
@login_required()
def analytics(patient_id=None):
    user = current_user()
    if patient_id is None:
        patient_id = user["id"] if user["role"] == "patient" else None
        if patient_id is None:
            flash("Choose a patient to view analytics for.", "error")
            return redirect(url_for("doctor_home"))

    if user["role"] == "patient" and user["id"] != patient_id:
        flash("You can only view your own analytics.", "error")
        return redirect(url_for("dashboard"))

    if user["role"] == "doctor":
        if not security.is_doctor_authorized(user["id"], patient_id):
            flash("Access denied: You do not have patient consent to view this patient's analytics.", "error")
            return redirect(url_for("doctor_home"))
        security.log_audit_access(user["id"], patient_id, "view_patient_analytics", request.remote_addr)

    with db.db_session() as conn:
        patient = conn.execute("SELECT * FROM users WHERE id = ?", (patient_id,)).fetchone()

    return render_template("analytics.html", patient=patient, user=user)


# ---------------------------------------------------------------------------
# Patient: Consent & Audit Log Views
# ---------------------------------------------------------------------------

@app.route("/doctor-access")
@login_required(role="patient")
def doctor_access():
    user = current_user()
    doctors = security.get_patient_consents(user["id"])
    return render_template("doctor_access.html", doctors=doctors, user=user)


@app.route("/doctor-access/toggle", methods=["POST"])
@login_required(role="patient")
def toggle_doctor_access():
    user = current_user()
    doctor_id = int(request.form["doctor_id"])
    action = request.form.get("action", "grant")
    if action == "grant":
        security.grant_doctor_consent(user["id"], doctor_id)
        flash("Doctor access authorization granted.", "success")
    else:
        security.revoke_doctor_consent(user["id"], doctor_id)
        flash("Doctor access authorization revoked.", "success")
    return redirect(url_for("doctor_access"))


@app.route("/audit-log")
@login_required(role="patient")
def audit_log_view():
    user = current_user()
    audit_entries = security.get_patient_audit_trail(user["id"])
    return render_template("audit_log.html", audit_entries=audit_entries, user=user)


# ---------------------------------------------------------------------------
# Blockchain Timeline
# ---------------------------------------------------------------------------

@app.route("/blockchain")
@app.route("/blockchain-timeline")
@login_required()
def blockchain_view():
    with db.db_session() as conn:
        blocks = conn.execute("SELECT * FROM blocks ORDER BY idx ASC").fetchall()
        block_list = []
        for b in blocks:
            data = json.loads(b["data"])
            patient_name = None
            if "patient_id" in data:
                p = conn.execute("SELECT name FROM users WHERE id = ?", (data["patient_id"],)).fetchone()
                patient_name = p["name"] if p else f"User #{data['patient_id']}"
            block_list.append({
                "idx": b["idx"], "hash": b["hash"], "previous_hash": b["previous_hash"],
                "timestamp": datetime.fromtimestamp(b["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"),
                "data": data, "patient_name": patient_name,
            })
    return render_template("blockchain.html", blocks=block_list)


# ---------------------------------------------------------------------------
# Doctor views
# ---------------------------------------------------------------------------

@app.route("/doctor")
@login_required(role="doctor")
def doctor_home():
    user = current_user()
    with db.db_session() as conn:
        # Phase 1: Only display patients who have granted approved consent to this doctor
        patients = conn.execute(
            """SELECT u.*,
                      (SELECT COUNT(*) FROM health_records hr WHERE hr.patient_id = u.id) as record_count,
                      (SELECT recorded_at FROM health_records hr WHERE hr.patient_id = u.id ORDER BY recorded_at DESC LIMIT 1) as last_update
               FROM users u
               JOIN doctor_patient_consent c ON c.patient_id = u.id
               WHERE u.role = 'patient' AND c.doctor_id = ? AND c.status = 'approved'
               ORDER BY u.name""",
            (user["id"],),
        ).fetchall()

    patient_rows = []
    for p in patients:
        latest = None
        with db.db_session() as conn:
            latest = conn.execute(
                "SELECT * FROM health_records WHERE patient_id = ? ORDER BY recorded_at DESC LIMIT 1",
                (p["id"],),
            ).fetchone()
        status = "no-data"
        if latest:
            organs = db.organ_status_from_vitals(
                latest["heart_rate"], latest["bp_sys"], latest["bp_dia"],
                latest["oxygen_level"], latest["temperature"],
            )
            status = db.overall_status(organs)
        patient_rows.append({"patient": p, "status": status})

    return render_template("doctor_home.html", patient_rows=patient_rows)


@app.route("/doctor/patient/<int:patient_id>")
@login_required(role="doctor")
def doctor_patient(patient_id):
    user = current_user()
    # Phase 1: Enforce patient consent authorization
    if not security.is_doctor_authorized(user["id"], patient_id):
        flash("Access denied: You do not have approved patient consent to view this health record.", "error")
        return redirect(url_for("doctor_home"))

    # Phase 1: Record access in audit log
    security.log_audit_access(user["id"], patient_id, "view_patient_digital_twin", request.remote_addr)

    with db.db_session() as conn:
        patient = conn.execute("SELECT * FROM users WHERE id = ? AND role='patient'", (patient_id,)).fetchone()
        if not patient:
            flash("Patient not found.", "error")
            return redirect(url_for("doctor_home"))
        latest = conn.execute(
            "SELECT * FROM health_records WHERE patient_id = ? ORDER BY recorded_at DESC LIMIT 1",
            (patient_id,),
        ).fetchone()

    organs = overall = None
    if latest:
        organs = db.organ_status_from_vitals(
            latest["heart_rate"], latest["bp_sys"], latest["bp_dia"],
            latest["oxygen_level"], latest["temperature"],
        )
        overall = db.overall_status(organs)

    return render_template("dashboard.html", user=patient, latest=latest, organs=organs,
                            overall=overall, record_count=None, doctor_view=True)


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.route("/admin")
@login_required(role="admin")
def admin_home():
    with db.db_session() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY role, name").fetchall()
        record_total = conn.execute("SELECT COUNT(*) c FROM health_records").fetchone()["c"]
        block_total = conn.execute("SELECT COUNT(*) c FROM blocks").fetchone()["c"]
        recent_activity = conn.execute(
            """SELECT a.*, u.name FROM activity_log a LEFT JOIN users u ON u.id = a.user_id
               ORDER BY a.created_at DESC LIMIT 15"""
        ).fetchall()
    return render_template("admin.html", users=users, record_total=record_total,
                            block_total=block_total, recent_activity=recent_activity)


@app.route("/admin/doctor/create", methods=["POST"])
@login_required(role="admin")
def admin_create_doctor():
    name = request.form["name"].strip()
    email = request.form["email"].strip().lower()
    password = request.form["password"]

    with db.db_session() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            flash("An account with that email already exists.", "error")
            return redirect(url_for("admin_home"))

        conn.execute(
            "INSERT INTO users (name, email, password_hash, role, status) VALUES (?, ?, ?, 'doctor', 'active')",
            (name, email, generate_password_hash(password)),
        )
    flash(f"Doctor account for Dr. {name} created and approved.", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/doctor/<int:user_id>/status", methods=["POST"])
@login_required(role="admin")
def admin_toggle_doctor_status(user_id):
    with db.db_session() as conn:
        u = conn.execute("SELECT status, role, name FROM users WHERE id = ?", (user_id,)).fetchone()
        if not u or u["role"] != "doctor":
            flash("Doctor account not found.", "error")
            return redirect(url_for("admin_home"))

        curr_status = u["status"] if "status" in u.keys() and u["status"] else "active"
        new_status = "suspended" if curr_status == "active" else "active"
        conn.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))

    flash(f"Doctor account Dr. {u['name']} status updated to {new_status}.", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/verify")
@login_required(role="admin")
def admin_verify():
    with db.db_session() as conn:
        blocks = conn.execute("SELECT * FROM blocks ORDER BY idx ASC").fetchall()
        block_dicts = [dict(b) for b in blocks]

    is_valid, broken_at, report = bc.verify_chain(block_dicts)
    return jsonify({"is_valid": is_valid, "broken_at": broken_at, "report": report})



if __name__ == "__main__":
    init_app()
    app.run(debug=True, port=5000)
