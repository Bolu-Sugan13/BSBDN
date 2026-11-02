import pytest
from app import app, init_app

def test_csrf_protection_active():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = True
    init_app()
    with app.test_client() as client:
        # POST without CSRF token should return 400 Bad Request
        res = client.post("/login", data={"email": "admin@bsbdn.local", "password": "wrong"})
        assert res.status_code == 400
        assert b"CSRF" in res.data or b"Bad Request" in res.data
