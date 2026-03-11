from flask import Blueprint, request, jsonify
from config import db
import bcrypt
from functools import wraps

auth_bp = Blueprint("auth", __name__)

login_collection = db["login"]

# BASIC AUTH REQUIRED
def basic_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        auth = request.authorization

        if not auth:
            return jsonify({"error": "Authentication required"}), 401

        email = auth.username
        password = auth.password

        user = login_collection.find_one({"email": email})

        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            return jsonify({"error": "Invalid credentials"}), 401

        return f(*args, **kwargs)

    return decorated


# ADMIN REQUIRED
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        auth = request.authorization

        if not auth:
            return jsonify({"error": "Authentication required"}), 401

        email = auth.username
        password = auth.password

        user = login_collection.find_one({"email": email})

        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            return jsonify({"error": "Invalid credentials"}), 401

        if user["role"] != "admin":
            return jsonify({"error": "Admin access required"}), 403

        return f(*args, **kwargs)

    return decorated