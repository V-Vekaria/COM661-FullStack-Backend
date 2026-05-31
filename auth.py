from flask import Blueprint, request, jsonify
from config import get_db
from middleware.auth_middleware import blacklisted_tokens, require_auth, decode_token
import bcrypt
import jwt
import datetime
import os

auth_bp = Blueprint("auth", __name__)
SECRET = os.getenv("JWT_SECRET_KEY", "dev-only-secret-change-me")


@auth_bp.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True)

    # Missing or empty body
    if not body:
        return jsonify({"error": "Request body required"}), 400
    if "email" not in body:
        return jsonify({"error": "email is required", "field": "email"}), 400
    if "password" not in body:
        return jsonify({"error": "password is required", "field": "password"}), 400

    db = get_db()
    login_doc = db["login"].find_one({"email": body["email"]})

    if not login_doc:
        return jsonify({"error": "Invalid credentials"}), 401

    # Check password
    if not bcrypt.checkpw(body["password"].encode("utf-8"), login_doc["password"].encode("utf-8")):
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode(
        {
            "email": login_doc["email"],
            "role":  login_doc["role"],
            "user_id": str(login_doc["user_id"]),
            "exp":   datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        },
        SECRET,
        algorithm="HS256",
    )

    return jsonify({"token": token, "role": login_doc["role"], "email": login_doc["email"]}), 200


@auth_bp.route("/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("x-access-token")
    blacklisted_tokens.add(token)
    return jsonify({"message": "Logged out successfully"}), 200


@auth_bp.route("/me", methods=["GET"])
@require_auth
def me():
    user = request.current_user
    return jsonify({"email": user["email"], "role": user["role"], "user_id": user["user_id"]}), 200
