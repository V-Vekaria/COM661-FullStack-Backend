import os
import datetime
from functools import wraps

import bcrypt
import jwt
from flask import Blueprint, jsonify, make_response, request

from config import db

auth_bp = Blueprint("auth", __name__)
login_collection = db["login"]

SECRET_KEY = os.environ.get("SECRET_KEY", "saas-monitoring-secret-2026")


# ---------------------------------------------------------------------------
# LOGIN
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return make_response(jsonify({"error": "Invalid or missing JSON body"}), 400)

    email    = data.get("email", "").strip()
    password = data.get("password", "")

    if not email or not password:
        return make_response(jsonify({"error": "Email and password required"}), 400)

    user = login_collection.find_one({"email": email})
    if not user:
        return make_response(jsonify({"error": "Invalid credentials"}), 401)

    if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        return make_response(jsonify({"error": "Invalid credentials"}), 401)

    role = user["role"]
    if role not in ("admin", "analyst"):
        return make_response(jsonify({"error": "Access denied"}), 403)

    token = jwt.encode(
        {
            "user":    email,
            "role":    role,
            "user_id": str(user.get("user_id", "")),
            "exp":     datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=24),
        },
        SECRET_KEY,
        algorithm="HS256",
    )

    return make_response(jsonify({"token": token, "role": role, "email": email}), 200)


# ---------------------------------------------------------------------------
# GET /me  — returns current operator info from token
# ---------------------------------------------------------------------------

@auth_bp.route("/me", methods=["GET"])
def get_me():
    token = request.headers.get("x-access-token")
    if not token:
        return make_response(jsonify({"error": "Token is missing"}), 401)
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return make_response(jsonify({"error": "Token has expired"}), 401)
    except jwt.InvalidTokenError:
        return make_response(jsonify({"error": "Token is invalid"}), 401)

    return make_response(jsonify({
        "email":   data["user"],
        "role":    data["role"],
        "user_id": data.get("user_id", ""),
    }), 200)


# ---------------------------------------------------------------------------
# DECORATORS
# ---------------------------------------------------------------------------

def _decode_token():
    """Return decoded payload or None."""
    token = request.headers.get("x-access-token")
    if not token:
        return None, make_response(jsonify({"error": "Token is missing"}), 401)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, make_response(jsonify({"error": "Token has expired"}), 401)
    except jwt.InvalidTokenError:
        return None, make_response(jsonify({"error": "Token is invalid"}), 401)


def token_required(f):
    """Any valid JWT (admin or analyst)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        payload, err = _decode_token()
        if err:
            return err
        if payload["role"] not in ("admin", "analyst"):
            return make_response(jsonify({"error": "Access denied"}), 403)
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Admin only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        payload, err = _decode_token()
        if err:
            return err
        if payload["role"] != "admin":
            return make_response(jsonify({"error": "Admin access required"}), 403)
        return f(*args, **kwargs)
    return decorated


def analyst_or_admin(f):
    """Read/acknowledge endpoints — both roles allowed."""
    @wraps(f)
    def decorated(*args, **kwargs):
        payload, err = _decode_token()
        if err:
            return err
        if payload["role"] not in ("admin", "analyst"):
            return make_response(jsonify({"error": "Access denied"}), 403)
        return f(*args, **kwargs)
    return decorated


# kept so nothing breaks during transition
basic_auth_required = token_required