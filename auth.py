from flask import Blueprint, request, jsonify
from config import db
import bcrypt
import jwt
from functools import wraps
from datetime import datetime, timedelta


auth_bp = Blueprint("auth", __name__)
login_collection = db["login"]
SECRET_KEY = "com661-secret"


# LOGIN
@auth_bp.route("/login", methods=["POST"])
def login():

    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = login_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode('utf-8')):
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode(
        {
            "user_id": str(user["_id"]),
            "email": user["email"],
            "role": user["role"],
            "user_id": user['user_id'],
            "exp": datetime.utcnow() + timedelta(minutes=30)
        },
        SECRET_KEY,
        algorithm="HS256"
    )
    return jsonify({"token": token}), 200


# JWT REQUIRED
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"error": "Token missing"}), 401
        token = token.split(" ")[1]

        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


# ADMIN REQUIRED
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token missing"}), 401
        token = token.split(" ")[1]

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

            if data["role"] != "admin":
                return jsonify({"error": "Admin access required"}), 403
        except:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated