"""Run once to set up the database and create a default admin account."""
from werkzeug.security import generate_password_hash
import database as db
from app import init_app

init_app()

with db.db_session() as conn:
    existing = conn.execute("SELECT id FROM users WHERE email = ?", ("admin@bsbdn.local",)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ("System Admin", "admin@bsbdn.local", generate_password_hash("admin123"), "admin"),
        )
        print("Created admin account: admin@bsbdn.local / admin123")
    else:
        print("Admin account already exists.")

print("Database ready at bsbdn.db")
