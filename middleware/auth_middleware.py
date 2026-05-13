from functools import wraps
from flask import request, jsonify
import jwt

SECRET = "saas-monitor-secret-key"

# Tokens invalidated by logout are stored here (in-memory blacklist)
blacklisted_tokens = set()


def decode_token(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"])


def require_auth(f):
    """Require a valid, non-blacklisted token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("x-access-token")
        if not token:
            return jsonify({"error": "Token missing"}), 401
        if token in blacklisted_tokens:
            return jsonify({"error": "Token has been invalidated"}), 401
        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token is invalid"}), 401
        request.current_user = payload
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Require admin role specifically."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("x-access-token")
        if not token:
            return jsonify({"error": "Token missing"}), 401
        if token in blacklisted_tokens:
            return jsonify({"error": "Token has been invalidated"}), 401
        try:
            payload = decode_token(token)
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token is invalid"}), 401
        if payload.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        request.current_user = payload
        return f(*args, **kwargs)
    return decorated


def require_admin_or_analyst(f):
    """Allow admin and analyst roles, block all others."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("x-access-token")
        if not token:
            return jsonify({"error": "Token missing"}), 401
        if token in blacklisted_tokens:
            return jsonify({"error": "Token has been invalidated"}), 401
        try:
            payload = decode_token(token)
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token is invalid"}), 401
        if payload.get("role") not in ("admin", "analyst"):
            return jsonify({"error": "Access denied"}), 403
        request.current_user = payload
        return f(*args, **kwargs)
    return decorated