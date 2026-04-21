from flask import Blueprint, request, jsonify, make_response
from config import db
import bcrypt
import jwt
import datetime
from functools import wraps

auth_bp = Blueprint("auth", __name__)
login_collection = db["login"]

SECRET_KEY = "saas-monitoring-secret-2026"


# --- LOGIN ---
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return make_response(jsonify({"error": "Email and password required"}), 400)

    user = login_collection.find_one({"email": email})
    if not user:
        return make_response(jsonify({"error": "Invalid credentials"}), 401)

    if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        return make_response(jsonify({"error": "Invalid credentials"}), 401)

    token = jwt.encode({
        "user": email,
        "role": user["role"],
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")

    return make_response(jsonify({
        "token": token,
        "role": user["role"],
        "email": email
    }), 200)


# --- DECORATORS (same pattern as BE08) ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            return make_response(jsonify({"error": "Token is missing"}), 401)
        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return make_response(jsonify({"error": "Token is invalid"}), 401)
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            return make_response(jsonify({"error": "Token is missing"}), 401)
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return make_response(jsonify({"error": "Token is invalid"}), 401)
        if data["role"] != "admin":
            return make_response(jsonify({"error": "Admin access required"}), 403)
        return f(*args, **kwargs)
    return decorated


# rename so user.py imports still work
basic_auth_required = token_required