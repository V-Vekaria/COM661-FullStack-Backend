"""Authentication endpoints for register/login."""
import bcrypt
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token
from config import db

auth_bp = Blueprint("auth", __name__)
users = db["users"]


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register new user account with engineer role default."""
    try:
        data = request.get_json() or {}
        missing = [f for f in ["name", "username", "password", "email"] if not data.get(f)]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
        if "@" not in data["email"]:
            return jsonify({"error": "Invalid email"}), 400
        if users.find_one({"username": data["username"]}):
            return jsonify({"error": "Username already exists"}), 409
        hashed = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode()
        doc = {"name": data["name"], "username": data["username"], "password": hashed, "email": data["email"], "role": data.get("role", "engineer")}
        users.insert_one(doc)
        return jsonify({"message": "User registered"}), 201
    except Exception:
        return jsonify({"error": "Server error"}), 500


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate user and return JWT access token."""
    try:
        data = request.get_json() or {}
        user = users.find_one({"username": data.get("username", "")})
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
        if not bcrypt.checkpw(data.get("password", "").encode(), user["password"].encode()):
            return jsonify({"error": "Invalid credentials"}), 401
        token = create_access_token(identity={"username": user["username"], "role": user["role"]})
        return jsonify({"message": "Login successful", "data": {"token": token}}), 200
    except Exception:
        return jsonify({"error": "Server error"}), 500
