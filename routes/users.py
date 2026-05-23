from flask import Blueprint, request, jsonify
from config import get_db
from middleware.auth_middleware import require_auth, require_admin, require_admin_or_analyst
from bson import ObjectId
import bcrypt
import re

users_bp = Blueprint("users", __name__)

VALID_TIERS    = {"free", "pro", "enterprise"}
VALID_ROLES    = {"admin", "analyst"}
VALID_STATUSES = {"active", "suspended", "inactive", "pending_verification"}
VALID_CHURN    = {"low", "medium", "high"}
VALID_REGIONS  = {"eu-west", "us-east", "us-west", "ap-south", "ap-northeast", "sa-east", "af-south"}
VALID_METHODS  = {"GET", "POST", "PUT", "DELETE", "PATCH"}
VALID_PERMS    = {"read", "write", "delete", "admin", "billing"}
VALID_SEVERITY = {"low", "medium", "high", "critical"}
VALID_ALERT_TYPES = {"threshold_breach", "security_event", "billing_alert", "performance_degradation"}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def to_json(doc):
    """Recursively convert ObjectId to string for JSON serialisation."""
    if isinstance(doc, list):
        return [to_json(d) for d in doc]
    if isinstance(doc, dict):
        return {k: to_json(v) for k, v in doc.items()}
    if isinstance(doc, ObjectId):
        return str(doc)
    return doc


# ---------------------------------------------------------------------------
# USERS
# ---------------------------------------------------------------------------

@users_bp.route("/users", methods=["POST"])
@require_admin
def create_user():
    body = request.get_json(silent=True) or {}

    if "email" not in body or "password" not in body:
        missing = "email" if "email" not in body else "password"
        return jsonify({"error": f"{missing} required", "field": missing}), 400

    # Validate email format
    if not EMAIL_RE.match(body["email"]):
        return jsonify({"error": "Invalid email format", "field": "email"}), 422

    # Validate password length (min 6 chars)
    if len(body["password"]) < 6:
        return jsonify({"error": "Password too short (min 6 chars)", "field": "password"}), 422

    # Validate role if provided
    role = body.get("role", "analyst")
    if role not in VALID_ROLES:
        return jsonify({"error": "Invalid role. Must be admin or analyst", "field": "role"}), 422

    # Validate subscription tier if provided
    tier = body.get("subscription_tier", "free")
    if tier not in VALID_TIERS:
        return jsonify({"error": "Invalid subscription tier", "field": "tier"}), 422

    db = get_db()

    # Check duplicate email
    if db["login"].find_one({"email": body["email"]}):
        return jsonify({"error": "Email already exists", "field": "email"}), 409

    user_id = ObjectId()
    hashed = bcrypt.hashpw(body["password"].encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    user_doc = {
        "_id": user_id,
        "profile": {
            "first_name": body.get("first_name", ""),
            "last_name":  body.get("last_name", ""),
            "email":      body["email"],
            "role":       role,
            "created_at": __import__("datetime").datetime.utcnow(),
        },
        "subscription": {
            "tier":   tier,
            "status": "active",
        },
        "usage_logs": [],
        "api_keys":   [],
        "alerts":     [],
        "metadata": {
            "churn_risk": "low",
        },
    }

    login_doc = {
        "email":    body["email"],
        "password": hashed,
        "role":     role,
        "user_id":  str(user_id),
    }

    db["users"].insert_one(user_doc)
    db["login"].insert_one(login_doc)

    return jsonify({"user_id": str(user_id)}), 201


@users_bp.route("/users", methods=["GET"])
@require_admin_or_analyst
def list_users():
    db = get_db()
    query = {}

    tier   = request.args.get("tier")
    status = request.args.get("status")

    if tier:
        query["subscription.tier"] = tier
    if status:
        query["subscription.status"] = status

    pn = int(request.args.get("pn", 1))
    ps = int(request.args.get("ps", 10))
    skip = (pn - 1) * ps

    total = db["users"].count_documents(query)
    users = list(db["users"].find(query).skip(skip).limit(ps))

    return jsonify({"users": to_json(users), "total": total, "page": pn, "page_size": ps}), 200


@users_bp.route("/users/search", methods=["GET"])
@require_admin_or_analyst
def search_users():
    args = request.args
    allowed = {"q", "email", "first_name", "last_name", "tier", "churn_risk"}

    if not any(k in args for k in allowed):
        return jsonify({"error": "At least one search parameter required"}), 400

    db = get_db()
    query = {}

    # Generic search across name and email fields
    if "q" in args:
        q = args["q"]
        query["$or"] = [
            {"profile.first_name": {"$regex": q, "$options": "i"}},
            {"profile.last_name":  {"$regex": q, "$options": "i"}},
            {"profile.email":      {"$regex": q, "$options": "i"}},
        ]
    else:
        if "email" in args:
            query["profile.email"] = {"$regex": args["email"], "$options": "i"}
        if "first_name" in args:
            query["profile.first_name"] = {"$regex": args["first_name"], "$options": "i"}
        if "last_name" in args:
            query["profile.last_name"] = {"$regex": args["last_name"], "$options": "i"}
        if "tier" in args:
            tiers = args["tier"].split(",")
            query["subscription.tier"] = {"$in": tiers}
        if "churn_risk" in args:
            query["metadata.churn_risk"] = args["churn_risk"]

    results = list(db["users"].find(query))
    return jsonify({"users": to_json(results), "count": len(results)}), 200


@users_bp.route("/users/<string:user_id>", methods=["GET"])
@require_admin_or_analyst
def get_user(user_id):
    db = get_db()
    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    user = db["users"].find_one({"_id": oid})
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(to_json(user)), 200


@users_bp.route("/users/<string:user_id>", methods=["PUT"])
@require_admin
def update_user(user_id):
    body = request.get_json(silent=True) or {}
    if not body:
        return jsonify({"error": "Request body required"}), 400

    db = get_db()
    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    updates = {}

    if "subscription_tier" in body:
        if body["subscription_tier"] not in VALID_TIERS:
            return jsonify({"error": "Invalid tier", "field": "tier"}), 422
        updates["subscription.tier"] = body["subscription_tier"]

    if "account_status" in body:
        if body["account_status"] not in VALID_STATUSES:
            return jsonify({"error": "Invalid status", "field": "account_status"}), 422
        updates["subscription.status"] = body["account_status"]

    if "churn_risk" in body:
        if body["churn_risk"] not in VALID_CHURN:
            return jsonify({"error": "Invalid churn_risk", "field": "churn_risk"}), 422
        updates["metadata.churn_risk"] = body["churn_risk"]

    if "email" in body:
        if not EMAIL_RE.match(body["email"]):
            return jsonify({"error": "Invalid email format", "field": "email"}), 422
        updates["profile.email"] = body["email"]

    if not updates:
        return jsonify({"error": "No valid fields provided"}), 400

    result = db["users"].update_one({"_id": oid}, {"$set": updates})
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User updated"}), 200


@users_bp.route("/users/<string:user_id>", methods=["DELETE"])
@require_admin
def delete_user(user_id):
    db = get_db()
    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    result = db["users"].delete_one({"_id": oid})
    if result.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404

    db["login"].delete_one({"user_id": user_id})
    return jsonify({"message": "User deleted"}), 200


# ---------------------------------------------------------------------------
# USAGE LOGS  (embedded in users collection)
# ---------------------------------------------------------------------------

@users_bp.route("/users/<string:user_id>/usage", methods=["POST"])
@require_admin
def add_usage_log(user_id):
    body = request.get_json(silent=True) or {}
    db = get_db()

    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    # Required fields
    if "api_calls" not in body:
        return jsonify({"error": "api_calls required", "field": "api_calls"}), 400
    if "storage_mb" not in body:
        return jsonify({"error": "storage_mb required", "field": "storage_mb"}), 400

    # Type + range validation
    if not isinstance(body["api_calls"], (int, float)) or isinstance(body["api_calls"], bool):
        return jsonify({"error": "api_calls must be a number", "field": "api_calls"}), 422
    if body["api_calls"] <= 0:
        return jsonify({"error": "api_calls must be > 0", "field": "api_calls"}), 422
    if not isinstance(body["storage_mb"], (int, float)) or isinstance(body["storage_mb"], bool):
        return jsonify({"error": "storage_mb must be a number", "field": "storage_mb"}), 422
    if body["storage_mb"] < 0:
        return jsonify({"error": "storage_mb must be >= 0", "field": "storage_mb"}), 422

    if "region" in body and body["region"] not in VALID_REGIONS:
        return jsonify({"error": "Invalid region", "field": "region"}), 422
    if "method" in body and body["method"] not in VALID_METHODS:
        return jsonify({"error": "Invalid HTTP method", "field": "method"}), 422

    if not db["users"].find_one({"_id": oid}):
        return jsonify({"error": "User not found"}), 404

    region = body.get("region", "eu-west")
    log_id = ObjectId()
    log = {
        "_id":       log_id,
        "timestamp": __import__("datetime").datetime.utcnow(),
        "metrics": {
            "api_calls":  body["api_calls"],
            "storage_mb": body["storage_mb"],
            "breakdown": {
                "reads":  int(body["api_calls"] * 0.6),
                "writes": int(body["api_calls"] * 0.4),
            },
        },
        "request": {
            "endpoint": body.get("endpoint", "/api/unknown"),
            "region":   region,
            "method":   body.get("method", "GET"),
        },
    }

    db["users"].update_one({"_id": oid}, {"$push": {"usage_logs": log}})
    return jsonify({"log_id": str(log_id)}), 201


@users_bp.route("/users/<string:user_id>/usage", methods=["GET"])
@require_admin_or_analyst
def get_usage_logs(user_id):
    db = get_db()
    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    user = db["users"].find_one({"_id": oid}, {"usage_logs": 1})
    if not user:
        return jsonify({"error": "User not found"}), 404

    pn = int(request.args.get("pn", 1))
    ps = int(request.args.get("ps", 10))
    logs = user.get("usage_logs", [])
    start = (pn - 1) * ps
    page  = logs[start: start + ps]

    return jsonify({"logs": to_json(page), "total": len(logs)}), 200


@users_bp.route("/users/<string:user_id>/usage/<string:log_id>", methods=["PUT"])
@require_admin
def update_usage_log(user_id, log_id):
    body = request.get_json(silent=True) or {}
    if not body:
        return jsonify({"error": "Request body required"}), 400

    db = get_db()
    try:
        u_oid = ObjectId(user_id)
        l_oid = ObjectId(log_id)
    except Exception:
        return jsonify({"error": "Invalid ID"}), 400

    if "api_calls" in body:
        if not isinstance(body["api_calls"], (int, float)) or isinstance(body["api_calls"], bool):
            return jsonify({"error": "api_calls must be a number", "field": "api_calls"}), 422
        if body["api_calls"] <= 0:
            return jsonify({"error": "api_calls must be > 0", "field": "api_calls"}), 422

    updates = {}
    if "api_calls" in body:
        updates["usage_logs.$.metrics.api_calls"] = body["api_calls"]
    if "storage_mb" in body:
        updates["usage_logs.$.metrics.storage_mb"] = body["storage_mb"]

    if not updates:
        return jsonify({"error": "No valid fields"}), 400

    result = db["users"].update_one(
        {"_id": u_oid, "usage_logs._id": l_oid},
        {"$set": updates}
    )
    if result.matched_count == 0:
        return jsonify({"error": "Log not found"}), 404

    return jsonify({"message": "Log updated"}), 200


@users_bp.route("/users/<string:user_id>/usage/<string:log_id>", methods=["DELETE"])
@require_admin
def delete_usage_log(user_id, log_id):
    db = get_db()
    try:
        u_oid = ObjectId(user_id)
        l_oid = ObjectId(log_id)
    except Exception:
        return jsonify({"error": "Invalid ID"}), 400

    result = db["users"].update_one(
        {"_id": u_oid},
        {"$pull": {"usage_logs": {"_id": l_oid}}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "Log deleted"}), 200


# ---------------------------------------------------------------------------
# API KEYS  (embedded in users collection)
# ---------------------------------------------------------------------------

@users_bp.route("/users/<string:user_id>/api-keys", methods=["POST"])
@require_admin
def add_api_key(user_id):
    body = request.get_json(silent=True) or {}
    db = get_db()

    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    perms = body.get("permissions", [])
    if not perms:
        return jsonify({"error": "permissions required and must not be empty", "field": "permissions"}), 422
    invalid = [p for p in perms if p not in VALID_PERMS]
    if invalid:
        return jsonify({"error": f"Invalid permissions: {invalid}", "field": "permissions"}), 422

    if not db["users"].find_one({"_id": oid}):
        return jsonify({"error": "User not found"}), 404

    import string, random
    rand_str = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    key_id     = ObjectId()
    key_prefix = f"sk_live_{rand_str}"

    key_doc = {
        "_id":        key_id,
        "key_prefix": key_prefix,
        "permissions": perms,
        "created_at": __import__("datetime").datetime.utcnow(),
        "revoked":    False,
    }

    db["users"].update_one({"_id": oid}, {"$push": {"api_keys": key_doc}})
    return jsonify({"key_id": str(key_id), "key_prefix": key_prefix}), 201


@users_bp.route("/users/<string:user_id>/api-keys", methods=["GET"])
@require_admin_or_analyst
def get_api_keys(user_id):
    db = get_db()
    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    user = db["users"].find_one({"_id": oid}, {"api_keys": 1})
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(to_json(user.get("api_keys", []))), 200


@users_bp.route("/users/<string:user_id>/api-keys/<string:key_id>/revoke", methods=["PUT"])
@require_admin
def revoke_api_key(user_id, key_id):
    db = get_db()
    try:
        u_oid = ObjectId(user_id)
        k_oid = ObjectId(key_id)
    except Exception:
        return jsonify({"error": "Invalid ID"}), 400

    result = db["users"].update_one(
        {"_id": u_oid, "api_keys._id": k_oid},
        {"$set": {"api_keys.$.revoked": True}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "Key not found"}), 404

    return jsonify({"message": "API key revoked"}), 200


@users_bp.route("/users/<string:user_id>/api-keys/<string:key_id>", methods=["DELETE"])
@require_admin
def delete_api_key(user_id, key_id):
    db = get_db()
    try:
        u_oid = ObjectId(user_id)
        k_oid = ObjectId(key_id)
    except Exception:
        return jsonify({"error": "Invalid ID"}), 400

    user = db["users"].find_one({"_id": u_oid, "api_keys._id": k_oid})
    if not user:
        return jsonify({"error": "Key not found"}), 404

    db["users"].update_one(
        {"_id": u_oid},
        {"$pull": {"api_keys": {"_id": k_oid}}}
    )
    return jsonify({"message": "API key deleted"}), 200


# ---------------------------------------------------------------------------
# ALERTS  (embedded in users collection)
# ---------------------------------------------------------------------------

@users_bp.route("/users/<string:user_id>/alerts", methods=["POST"])
@require_admin
def add_alert(user_id):
    body = request.get_json(silent=True) or {}
    db = get_db()

    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    if "message" not in body or not body["message"]:
        return jsonify({"error": "message required", "field": "message"}), 400

    if "severity" in body and body["severity"] not in VALID_SEVERITY:
        return jsonify({"error": "Invalid severity", "field": "severity"}), 422

    if "alert_type" in body and body["alert_type"] not in VALID_ALERT_TYPES:
        return jsonify({"error": "Invalid alert_type", "field": "alert_type"}), 422

    if not db["users"].find_one({"_id": oid}):
        return jsonify({"error": "User not found"}), 404

    alert_id = ObjectId()
    alert = {
        "_id":          alert_id,
        "message":      body["message"],
        "severity":     body.get("severity", "low"),
        "alert_type":   body.get("alert_type", "threshold_breach"),
        "triggered_at": __import__("datetime").datetime.utcnow(),
        "acknowledged": False,
    }

    db["users"].update_one({"_id": oid}, {"$push": {"alerts": alert}})
    return jsonify({"alert_id": str(alert_id)}), 201


@users_bp.route("/users/<string:user_id>/alerts", methods=["GET"])
@require_admin_or_analyst
def get_alerts(user_id):
    db = get_db()
    try:
        oid = ObjectId(user_id)
    except Exception:
        return jsonify({"error": "Invalid user ID"}), 400

    user = db["users"].find_one({"_id": oid}, {"alerts": 1})
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(to_json(user.get("alerts", []))), 200


@users_bp.route("/users/<string:user_id>/alerts/<string:alert_id>/acknowledge", methods=["PUT"])
@require_admin_or_analyst
def acknowledge_alert(user_id, alert_id):
    db = get_db()
    try:
        u_oid = ObjectId(user_id)
        a_oid = ObjectId(alert_id)
    except Exception:
        return jsonify({"error": "Invalid ID"}), 400

    result = db["users"].update_one(
        {"_id": u_oid, "alerts._id": a_oid},
        {"$set": {"alerts.$.acknowledged": True}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "Alert not found"}), 404

    return jsonify({"message": "Alert acknowledged"}), 200


@users_bp.route("/users/<string:user_id>/alerts/<string:alert_id>", methods=["DELETE"])
@require_admin
def delete_alert(user_id, alert_id):
    db = get_db()
    try:
        u_oid = ObjectId(user_id)
        a_oid = ObjectId(alert_id)
    except Exception:
        return jsonify({"error": "Invalid ID"}), 400

    user = db["users"].find_one({"_id": u_oid, "alerts._id": a_oid})
    if not user:
        return jsonify({"error": "Alert not found"}), 404

    db["users"].update_one({"_id": u_oid}, {"$pull": {"alerts": {"_id": a_oid}}})
    return jsonify({"message": "Alert deleted"}), 200