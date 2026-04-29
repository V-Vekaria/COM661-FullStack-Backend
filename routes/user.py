import random
import re
import string
from datetime import datetime

import bcrypt
from bson import ObjectId
from flask import Blueprint, jsonify, request

from auth import admin_required, analyst_or_admin
from config import db

user_bp = Blueprint("users", __name__)

users_col         = db["users"]
login_col         = db["login"]
activity_logs_col = db["activity_logs"]
anomaly_flags_col = db["anomaly_flags"]

# ---------------------------------------------------------------------------
# CONSTANTS — validation
# ---------------------------------------------------------------------------

VALID_ROLES       = {"admin", "analyst"}          # operator roles only
VALID_TIERS       = {"free", "pro", "enterprise"}
VALID_STATUSES    = {"active", "suspended", "inactive", "pending_verification"}
VALID_SEVERITIES  = {"low", "medium", "high", "critical"}
VALID_ALERT_TYPES = {"threshold_breach", "security_event", "billing_alert", "performance_degradation"}
VALID_REGIONS     = {"eu-west", "us-east", "us-west", "ap-south", "ap-northeast", "sa-east", "af-south"}
VALID_METHODS     = {"GET", "POST", "PUT", "DELETE", "PATCH"}

REGION_COORDS = {
    "eu-west":      {"type": "Point", "coordinates": [-0.1278,    51.5074]},
    "us-east":      {"type": "Point", "coordinates": [-77.0369,   38.9072]},
    "us-west":      {"type": "Point", "coordinates": [-122.4194,  37.7749]},
    "ap-south":     {"type": "Point", "coordinates": [72.8777,    19.0760]},
    "ap-northeast": {"type": "Point", "coordinates": [139.6917,   35.6895]},
    "sa-east":      {"type": "Point", "coordinates": [-46.6333,  -23.5505]},
    "af-south":     {"type": "Point", "coordinates": [18.4241,   -33.9249]},
}


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def build_id_query(id):
    return {"_id": ObjectId(id)} if ObjectId.is_valid(id) else {"_id": id}


def serialize_doc(doc):
    if isinstance(doc, list):
        return [serialize_doc(d) for d in doc]
    if isinstance(doc, dict):
        return {k: serialize_doc(v) for k, v in doc.items()}
    if isinstance(doc, ObjectId):
        return str(doc)
    if isinstance(doc, datetime):
        return doc.isoformat()
    return doc


def err(msg, field=None, code=400):
    body = {"error": msg}
    if field:
        body["field"] = field
    return jsonify(body), code


def validate_email(email):
    return bool(re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email))


def get_pagination():
    try:
        page_num  = max(1, int(request.args.get("pn", 1)))
        page_size = min(100, max(1, int(request.args.get("ps", 10))))
    except ValueError:
        page_num, page_size = 1, 10
    return page_num, page_size


# ---------------------------------------------------------------------------
# USERS
# ---------------------------------------------------------------------------

@user_bp.route("/users", methods=["POST"])
@admin_required
def create_user():
    data = request.get_json()
    if not data:
        return err("Invalid or missing JSON body")

    email      = data.get("email", "").strip()
    password   = data.get("password", "")
    tier       = data.get("subscription_tier", "free")
    first_name = data.get("first_name", "").strip()
    last_name  = data.get("last_name", "").strip()

    # validation
    if not email:
        return err("email is required", "email")
    if not validate_email(email):
        return err("Invalid email format", "email", 422)
    if not password or len(password) < 6:
        return err("password must be at least 6 characters", "password", 422)
    if tier not in VALID_TIERS:
        return err(f"tier must be one of: {', '.join(sorted(VALID_TIERS))}", "tier", 422)
    if users_col.find_one({"profile.email": email}):
        return err("Email already exists", "email", 409)

    hashed  = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user_id = ObjectId()

    user_doc = {
        "_id": user_id,
        "profile": {
            "first_name": first_name,
            "last_name":  last_name,
            "email":      email,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None,
        },
        "subscription": {
            "tier":           tier,
            "status":         "active",
            "billing_cycle":  "monthly",
            "renewal_date":   None,
            "seats_allocated": 1,
            "features_enabled": {
                "sso":                tier == "enterprise",
                "advanced_analytics": tier in ("pro", "enterprise"),
                "priority_support":   tier in ("pro", "enterprise"),
                "audit_logs":         tier == "enterprise",
                "custom_domains":     tier == "enterprise",
                "rate_limits": {
                    "requests_per_minute": 100 if tier == "free" else (500 if tier == "pro" else 2000),
                    "burst_capacity":      200 if tier == "free" else (1000 if tier == "pro" else 5000),
                    "throttle_enabled":    tier != "free",
                },
            },
            "billing": {
                "plan_price_usd": 0 if tier == "free" else (29.99 if tier == "pro" else 199.99),
                "payment_method": {
                    "type":      None,
                    "last_four": None,
                    "expires":   None,
                },
            },
        },
        "usage_logs": [],
        "api_keys":   [],
        "alerts":     [],
        "metadata": {
            "signup_source": data.get("signup_source", "organic"),
            "industry":      data.get("industry", ""),
            "company_size":  data.get("company_size", ""),
            "nps_score":     None,
            "churn_risk":    "low",
        },
    }

    users_col.insert_one(user_doc)
    return jsonify({"message": "User created", "user_id": str(user_id)}), 201


@user_bp.route("/users", methods=["GET"])
@admin_required
def get_users():
    page_num, page_size = get_pagination()
    skip = (page_num - 1) * page_size

    query = {}
    if request.args.get("tier"):
        query["subscription.tier"] = request.args.get("tier")
    if request.args.get("status"):
        query["subscription.status"] = request.args.get("status")

    projection = {"profile": 1, "subscription.tier": 1, "subscription.status": 1}
    total = users_col.count_documents(query)
    users = list(users_col.find(query, projection).skip(skip).limit(page_size))

    return jsonify({
        "total":    total,
        "page":     page_num,
        "per_page": page_size,
        "users":    serialize_doc(users),
    }), 200


@user_bp.route("/users/search", methods=["GET"])
@admin_required
def search_users():
    query = {}
    if request.args.get("email"):
        query["profile.email"] = {"$regex": request.args.get("email"), "$options": "i"}
    if request.args.get("tier"):
        query["subscription.tier"] = {"$in": request.args.get("tier").split(",")}
    if request.args.get("status"):
        query["subscription.status"] = request.args.get("status")
    if request.args.get("churn_risk"):
        query["metadata.churn_risk"] = request.args.get("churn_risk")
    if request.args.get("first_name"):
        query["profile.first_name"] = {"$regex": request.args.get("first_name"), "$options": "i"}
    if request.args.get("last_name"):
        query["profile.last_name"] = {"$regex": request.args.get("last_name"), "$options": "i"}

    if not query:
        return err("Provide at least one search parameter")

    projection = {
        "profile": 1,
        "subscription.tier": 1,
        "subscription.status": 1,
        "metadata.churn_risk": 1,
    }
    users = list(users_col.find(query, projection))
    return jsonify({"count": len(users), "users": serialize_doc(users)}), 200


@user_bp.route("/users/<string:id>", methods=["GET"])
@admin_required
def get_one_user(id):
    user = users_col.find_one(build_id_query(id))
    if user is None:
        return err("User not found", code=404)
    return jsonify(serialize_doc(user)), 200


@user_bp.route("/users/<string:id>", methods=["PUT"])
@admin_required
def update_user(id):
    data = request.get_json() or {}
    fields = {}

    if "email" in data:
        if not validate_email(data["email"]):
            return err("Invalid email format", "email", 422)
        fields["profile.email"] = data["email"].strip()
    if "first_name" in data:
        fields["profile.first_name"] = data["first_name"].strip()
    if "last_name" in data:
        fields["profile.last_name"] = data["last_name"].strip()
    if "subscription_tier" in data:
        if data["subscription_tier"] not in VALID_TIERS:
            return err(f"tier must be one of: {', '.join(sorted(VALID_TIERS))}", "subscription_tier", 422)
        fields["subscription.tier"] = data["subscription_tier"]
    if "account_status" in data:
        if data["account_status"] not in VALID_STATUSES:
            return err(f"status must be one of: {', '.join(sorted(VALID_STATUSES))}", "account_status", 422)
        fields["subscription.status"] = data["account_status"]
    if "churn_risk" in data:
        if data["churn_risk"] not in {"low", "medium", "high"}:
            return err("churn_risk must be low, medium or high", "churn_risk", 422)
        fields["metadata.churn_risk"] = data["churn_risk"]

    if not fields:
        return err("No valid fields provided to update")

    result = users_col.update_one(build_id_query(id), {"$set": fields})
    if result.matched_count == 0:
        return err("User not found", code=404)

    return jsonify({"message": "User updated"}), 200


@user_bp.route("/users/<string:id>", methods=["DELETE"])
@admin_required
def delete_user(id):
    result = users_col.delete_one(build_id_query(id))
    if result.deleted_count == 0:
        return err("User not found", code=404)
    login_col.delete_one({"user_id": id})
    return jsonify({"message": "User deleted"}), 200


# ---------------------------------------------------------------------------
# USAGE LOGS — sub-documents (4-level nesting via metrics.breakdown)
# ---------------------------------------------------------------------------

@user_bp.route("/users/<string:id>/usage", methods=["POST"])
@admin_required
def add_usage_log(id):
    data = request.get_json() or {}

    api_calls_raw  = data.get("api_calls")
    storage_mb_raw = data.get("storage_mb")
    region         = data.get("region", "eu-west")
    endpoint       = data.get("endpoint", "/api/upload")
    method         = data.get("method", "POST")

    if api_calls_raw is None or storage_mb_raw is None:
        return err("api_calls and storage_mb are required")

    try:
        api_calls  = int(api_calls_raw)
        storage_mb = float(storage_mb_raw)
    except (ValueError, TypeError):
        return err("api_calls must be integer, storage_mb must be number", code=422)

    if api_calls <= 0:
        return err("api_calls must be greater than 0", "api_calls", 422)
    if storage_mb <= 0:
        return err("storage_mb must be greater than 0", "storage_mb", 422)
    if region not in VALID_REGIONS:
        return err(f"region must be one of: {', '.join(sorted(VALID_REGIONS))}", "region", 422)
    if method not in VALID_METHODS:
        return err(f"method must be one of: {', '.join(VALID_METHODS)}", "method", 422)

    log = {
        "_id":       ObjectId(),
        "timestamp": datetime.utcnow().isoformat(),
        "metrics": {
            "api_calls":       api_calls,
            "storage_mb":      storage_mb,
            "bandwidth_gb":    round(storage_mb / 1024, 4),
            "active_sessions": data.get("active_sessions", 1),
            "breakdown": {                              # 4th nesting level
                "read_ops":       max(0, int(api_calls * 0.6)),
                "write_ops":      max(0, int(api_calls * 0.3)),
                "delete_ops":     max(0, int(api_calls * 0.1)),
                "cache_hit_pct":  data.get("cache_hit_pct", 75.0),
            },
        },
        "request": {
            "endpoint":         endpoint,
            "region":           region,
            "method":           method,
            "response_time_ms": data.get("response_time_ms", 200),
            "status_code":      200,
        },
        "location": REGION_COORDS.get(region, REGION_COORDS["eu-west"]),
    }

    result = users_col.update_one(build_id_query(id), {"$push": {"usage_logs": log}})
    if result.matched_count == 0:
        return err("User not found", code=404)

    return jsonify({"message": "Usage log added", "log_id": str(log["_id"])}), 201


@user_bp.route("/users/<string:id>/usage", methods=["GET"])
@analyst_or_admin
def get_usage_logs(id):
    user = users_col.find_one(build_id_query(id))
    if user is None:
        return err("User not found", code=404)

    logs      = user.get("usage_logs", [])
    page_num, page_size = get_pagination()
    total     = len(logs)
    start     = (page_num - 1) * page_size
    paginated = logs[start: start + page_size]

    return jsonify({
        "total":    total,
        "page":     page_num,
        "per_page": page_size,
        "logs":     serialize_doc(paginated),
    }), 200


@user_bp.route("/users/<string:user_id>/usage/<string:log_id>", methods=["PUT"])
@admin_required
def update_usage_log(user_id, log_id):
    data   = request.get_json() or {}
    fields = {}

    if "api_calls" in data:
        try:
            v = int(data["api_calls"])
        except (ValueError, TypeError):
            return err("api_calls must be an integer", "api_calls", 422)
        if v <= 0:
            return err("api_calls must be greater than 0", "api_calls", 422)
        fields["usage_logs.$.metrics.api_calls"] = v

    if "storage_mb" in data:
        try:
            v = float(data["storage_mb"])
        except (ValueError, TypeError):
            return err("storage_mb must be a number", "storage_mb", 422)
        if v <= 0:
            return err("storage_mb must be greater than 0", "storage_mb", 422)
        fields["usage_logs.$.metrics.storage_mb"] = v

    if "endpoint" in data:
        fields["usage_logs.$.request.endpoint"] = data["endpoint"]

    if not fields:
        return err("No valid fields provided to update")

    log_oid = ObjectId(log_id) if ObjectId.is_valid(log_id) else log_id
    result  = users_col.update_one(
        {**build_id_query(user_id), "usage_logs._id": log_oid},
        {"$set": fields},
    )
    if result.matched_count == 0:
        return err("User or usage log not found", code=404)

    return jsonify({"message": "Usage log updated"}), 200


@user_bp.route("/users/<string:user_id>/usage/<string:log_id>", methods=["DELETE"])
@admin_required
def delete_usage_log(user_id, log_id):
    log_oid = ObjectId(log_id) if ObjectId.is_valid(log_id) else log_id
    result  = users_col.update_one(
        build_id_query(user_id),
        {"$pull": {"usage_logs": {"_id": log_oid}}},
    )
    if result.matched_count == 0:
        return err("User not found", code=404)
    return jsonify({"message": "Usage log deleted"}), 200


# ---------------------------------------------------------------------------
# API KEYS — sub-documents
# ---------------------------------------------------------------------------

@user_bp.route("/users/<string:id>/api-keys", methods=["POST"])
@admin_required
def add_api_key(id):
    user = users_col.find_one(build_id_query(id))
    if user is None:
        return err("User not found", code=404)

    data        = request.get_json() or {}
    tier        = user.get("subscription", {}).get("tier", "free")
    permissions = data.get("permissions", ["read"])
    env         = "live" if tier != "free" else "test"

    if not isinstance(permissions, list) or not permissions:
        return err("permissions must be a non-empty list", "permissions", 422)

    invalid_perms = set(permissions) - {"read", "write", "delete", "admin", "billing"}
    if invalid_perms:
        return err(f"Invalid permissions: {', '.join(invalid_perms)}", "permissions", 422)

    rand_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    key = {
        "_id":        ObjectId(),
        "key_prefix": f"sk_{env}_{rand_suffix}",
        "created_at": datetime.utcnow().isoformat(),
        "last_used":  None,
        "revoked":    False,
        "permissions": permissions,
    }

    users_col.update_one(build_id_query(id), {"$push": {"api_keys": key}})
    return jsonify({"message": "API key created", "key_id": str(key["_id"]), "key_prefix": key["key_prefix"]}), 201


@user_bp.route("/users/<string:id>/api-keys", methods=["GET"])
@analyst_or_admin
def get_api_keys(id):
    user = users_col.find_one(build_id_query(id))
    if user is None:
        return err("User not found", code=404)
    return jsonify(serialize_doc(user.get("api_keys", []))), 200


@user_bp.route("/users/<string:user_id>/api-keys/<string:key_id>/revoke", methods=["PUT"])
@admin_required
def revoke_api_key(user_id, key_id):
    key_oid = ObjectId(key_id) if ObjectId.is_valid(key_id) else key_id
    result  = users_col.update_one(
        {**build_id_query(user_id), "api_keys._id": key_oid},
        {"$set": {"api_keys.$.revoked": True}},
    )
    if result.matched_count == 0:
        return err("User or API key not found", code=404)
    return jsonify({"message": "API key revoked"}), 200


@user_bp.route("/users/<string:user_id>/api-keys/<string:key_id>", methods=["DELETE"])
@admin_required
def delete_api_key(user_id, key_id):
    key_oid = ObjectId(key_id) if ObjectId.is_valid(key_id) else key_id
    result  = users_col.update_one(
        build_id_query(user_id),
        {"$pull": {"api_keys": {"_id": key_oid}}},
    )
    if result.matched_count == 0:
        return err("User not found", code=404)
    return jsonify({"message": "API key deleted"}), 200


# ---------------------------------------------------------------------------
# ALERTS — sub-documents
# ---------------------------------------------------------------------------

@user_bp.route("/users/<string:id>/alerts", methods=["POST"])
@admin_required
def add_alert(id):
    data       = request.get_json() or {}
    message    = data.get("message", "").strip()
    severity   = data.get("severity", "medium")
    alert_type = data.get("alert_type", "threshold_breach")

    if not message:
        return err("message is required", "message")
    if severity not in VALID_SEVERITIES:
        return err(f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}", "severity", 422)
    if alert_type not in VALID_ALERT_TYPES:
        return err(f"alert_type must be one of: {', '.join(sorted(VALID_ALERT_TYPES))}", "alert_type", 422)

    alert = {
        "_id":          ObjectId(),
        "alert_type":   alert_type,
        "message":      message,
        "severity":     severity,
        "triggered_at": datetime.utcnow().isoformat(),
        "acknowledged": False,
    }

    result = users_col.update_one(build_id_query(id), {"$push": {"alerts": alert}})
    if result.matched_count == 0:
        return err("User not found", code=404)

    return jsonify({"message": "Alert added", "alert_id": str(alert["_id"])}), 201


@user_bp.route("/users/<string:id>/alerts", methods=["GET"])
@analyst_or_admin
def get_alerts(id):
    user = users_col.find_one(build_id_query(id))
    if user is None:
        return err("User not found", code=404)
    return jsonify(serialize_doc(user.get("alerts", []))), 200


@user_bp.route("/users/<string:user_id>/alerts/<string:alert_id>/acknowledge", methods=["PUT"])
@analyst_or_admin
def acknowledge_alert(user_id, alert_id):
    alert_oid = ObjectId(alert_id) if ObjectId.is_valid(alert_id) else alert_id
    result    = users_col.update_one(
        {**build_id_query(user_id), "alerts._id": alert_oid},
        {"$set": {"alerts.$.acknowledged": True}},
    )
    if result.matched_count == 0:
        return err("User or alert not found", code=404)
    return jsonify({"message": "Alert acknowledged"}), 200


@user_bp.route("/users/<string:user_id>/alerts/<string:alert_id>", methods=["DELETE"])
@admin_required
def delete_alert(user_id, alert_id):
    alert_oid = ObjectId(alert_id) if ObjectId.is_valid(alert_id) else alert_id
    result    = users_col.update_one(
        build_id_query(user_id),
        {"$pull": {"alerts": {"_id": alert_oid}}},
    )
    if result.matched_count == 0:
        return err("User not found", code=404)
    return jsonify({"message": "Alert deleted"}), 200


# ---------------------------------------------------------------------------
# ACTIVITY LOGS — standalone collection
# ---------------------------------------------------------------------------

@user_bp.route("/activity-logs", methods=["POST"])
@admin_required
def create_activity_log():
    data        = request.get_json() or {}
    user_id     = data.get("user_id", "")
    action_type = data.get("action_type", "").strip()

    if not user_id:
        return err("user_id is required", "user_id")
    if not action_type:
        return err("action_type is required", "action_type")

    region = data.get("region", "eu-west")
    if region not in VALID_REGIONS:
        return err(f"region must be one of: {', '.join(sorted(VALID_REGIONS))}", "region", 422)

    try:
        response_time = int(data.get("response_time_ms", 200))
        status_code   = int(data.get("status_code", 200))
        bytes_tx      = int(data.get("bytes_transferred", 0))
    except (ValueError, TypeError):
        return err("response_time_ms, status_code, bytes_transferred must be integers", code=422)

    if response_time < 0:
        return err("response_time_ms must be >= 0", "response_time_ms", 422)
    if status_code < 100 or status_code > 599:
        return err("status_code must be a valid HTTP status (100-599)", "status_code", 422)

    log = {
        "user_id":     ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id,
        "user_email":  data.get("user_email", ""),
        "action_type": action_type,
        "resource": {
            "id":   data.get("resource_id", ""),
            "type": data.get("resource_type", "file"),
            "name": data.get("resource_name", ""),
        },
        "network": {
            "ip_address":  data.get("ip_address", "0.0.0.0"),
            "device_type": data.get("device_type", "desktop"),
            "region":      region,
            "location":    REGION_COORDS.get(region, REGION_COORDS["eu-west"]),
        },
        "performance": {
            "response_time_ms":  response_time,
            "status_code":       status_code,
            "bytes_transferred": bytes_tx,
        },
        "timestamp":  datetime.utcnow().isoformat(),
        "session_id": data.get("session_id", ""),
    }

    result = activity_logs_col.insert_one(log)
    return jsonify({"message": "Activity log created", "log_id": str(result.inserted_id)}), 201


@user_bp.route("/activity-logs", methods=["GET"])
@analyst_or_admin
def get_activity_logs():
    page_num, page_size = get_pagination()
    skip = (page_num - 1) * page_size

    query = {}
    if request.args.get("user_id"):
        uid = request.args.get("user_id")
        query["user_id"] = ObjectId(uid) if ObjectId.is_valid(uid) else uid
    if request.args.get("action_type"):
        query["action_type"] = request.args.get("action_type")
    if request.args.get("region"):
        query["network.region"] = request.args.get("region")
    if request.args.get("status_code"):
        try:
            query["performance.status_code"] = int(request.args.get("status_code"))
        except ValueError:
            return err("status_code must be an integer", "status_code", 422)

    date_filter = {}
    if request.args.get("from"):
        date_filter["$gte"] = request.args.get("from")
    if request.args.get("to"):
        date_filter["$lte"] = request.args.get("to")
    if date_filter:
        query["timestamp"] = date_filter

    total = activity_logs_col.count_documents(query)
    logs  = list(activity_logs_col.find(query).sort("timestamp", -1).skip(skip).limit(page_size))

    return jsonify({
        "total":    total,
        "page":     page_num,
        "per_page": page_size,
        "logs":     serialize_doc(logs),
    }), 200


@user_bp.route("/activity-logs/<string:id>", methods=["GET"])
@analyst_or_admin
def get_activity_log(id):
    log = activity_logs_col.find_one(build_id_query(id))
    if log is None:
        return err("Activity log not found", code=404)
    return jsonify(serialize_doc(log)), 200


@user_bp.route("/activity-logs/<string:id>", methods=["PUT"])
@admin_required
def update_activity_log(id):
    data   = request.get_json() or {}
    fields = {}

    if "action_type" in data:
        fields["action_type"] = data["action_type"]
    if "status_code" in data:
        try:
            sc = int(data["status_code"])
        except (ValueError, TypeError):
            return err("status_code must be an integer", "status_code", 422)
        if sc < 100 or sc > 599:
            return err("status_code must be 100-599", "status_code", 422)
        fields["performance.status_code"] = sc
    if "response_time_ms" in data:
        try:
            rt = int(data["response_time_ms"])
        except (ValueError, TypeError):
            return err("response_time_ms must be an integer", "response_time_ms", 422)
        if rt < 0:
            return err("response_time_ms must be >= 0", "response_time_ms", 422)
        fields["performance.response_time_ms"] = rt

    if not fields:
        return err("No valid fields provided to update")

    result = activity_logs_col.update_one(build_id_query(id), {"$set": fields})
    if result.matched_count == 0:
        return err("Activity log not found", code=404)

    return jsonify({"message": "Activity log updated"}), 200


@user_bp.route("/activity-logs/<string:id>", methods=["DELETE"])
@admin_required
def delete_activity_log(id):
    result = activity_logs_col.delete_one(build_id_query(id))
    if result.deleted_count == 0:
        return err("Activity log not found", code=404)
    return jsonify({"message": "Activity log deleted"}), 200


# ---------------------------------------------------------------------------
# ANOMALY FLAGS — standalone collection with resolution sub-documents
# ---------------------------------------------------------------------------

@user_bp.route("/anomaly-flags", methods=["POST"])
@admin_required
def create_anomaly_flag():
    data    = request.get_json() or {}
    user_id = data.get("user_id", "")
    reason  = data.get("reason", "").strip()

    if not user_id:
        return err("user_id is required", "user_id")
    if not reason:
        return err("reason is required", "reason")

    severity = data.get("severity", "medium")
    category = data.get("category", "security")

    if severity not in VALID_SEVERITIES:
        return err(f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}", "severity", 422)
    if category not in {"security", "performance", "billing", "compliance"}:
        return err("category must be: security, performance, billing or compliance", "category", 422)

    try:
        anomaly_score = float(data.get("anomaly_score", 0.5))
    except (ValueError, TypeError):
        return err("anomaly_score must be a number", "anomaly_score", 422)
    if not 0.0 <= anomaly_score <= 1.0:
        return err("anomaly_score must be between 0.0 and 1.0", "anomaly_score", 422)

    flag = {
        "user_id":    ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id,
        "user_email": data.get("user_email", ""),
        "reason":     reason,
        "anomaly_score": anomaly_score,
        "severity":   severity,
        "category":   category,
        "detected_at": datetime.utcnow().isoformat(),
        "resolved":   False,
        "resolution_logs": [],
        "evidence": {
            "failed_login_count":  int(data.get("failed_login_count", 0)),
            "suspicious_ips":      data.get("suspicious_ips", []),
            "time_window_hours":   int(data.get("time_window_hours", 24)),
            "flagged_endpoints":   data.get("flagged_endpoints", []),
            "countries_accessed":  data.get("countries_accessed", []),
        },
        "auto_actions_taken": {
            "account_locked":    False,
            "notification_sent": True,
            "admin_alerted":     True,
        },
    }

    result = anomaly_flags_col.insert_one(flag)
    return jsonify({"message": "Anomaly flag created", "flag_id": str(result.inserted_id)}), 201


@user_bp.route("/anomaly-flags", methods=["GET"])
@analyst_or_admin
def get_anomaly_flags():
    page_num, page_size = get_pagination()
    skip = (page_num - 1) * page_size

    query = {}
    if request.args.get("severity"):
        if request.args.get("severity") not in VALID_SEVERITIES:
            return err(f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}", "severity", 422)
        query["severity"] = request.args.get("severity")
    if request.args.get("category"):
        query["category"] = request.args.get("category")
    if request.args.get("resolved"):
        query["resolved"] = request.args.get("resolved").lower() == "true"

    total = anomaly_flags_col.count_documents(query)
    flags = list(anomaly_flags_col.find(query).sort("detected_at", -1).skip(skip).limit(page_size))

    return jsonify({
        "total":    total,
        "page":     page_num,
        "per_page": page_size,
        "flags":    serialize_doc(flags),
    }), 200


@user_bp.route("/anomaly-flags/<string:id>", methods=["GET"])
@analyst_or_admin
def get_anomaly_flag(id):
    flag = anomaly_flags_col.find_one(build_id_query(id))
    if flag is None:
        return err("Anomaly flag not found", code=404)
    return jsonify(serialize_doc(flag)), 200


@user_bp.route("/anomaly-flags/<string:id>", methods=["PUT"])
@admin_required
def update_anomaly_flag(id):
    data   = request.get_json() or {}
    fields = {}

    if "severity" in data:
        if data["severity"] not in VALID_SEVERITIES:
            return err(f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}", "severity", 422)
        fields["severity"] = data["severity"]
    if "resolved" in data:
        fields["resolved"] = bool(data["resolved"])
    if "anomaly_score" in data:
        try:
            s = float(data["anomaly_score"])
        except (ValueError, TypeError):
            return err("anomaly_score must be a number", "anomaly_score", 422)
        if not 0.0 <= s <= 1.0:
            return err("anomaly_score must be between 0.0 and 1.0", "anomaly_score", 422)
        fields["anomaly_score"] = s

    if not fields:
        return err("No valid fields provided to update")

    result = anomaly_flags_col.update_one(build_id_query(id), {"$set": fields})
    if result.matched_count == 0:
        return err("Anomaly flag not found", code=404)

    return jsonify({"message": "Anomaly flag updated"}), 200


@user_bp.route("/anomaly-flags/<string:id>", methods=["DELETE"])
@admin_required
def delete_anomaly_flag(id):
    result = anomaly_flags_col.delete_one(build_id_query(id))
    if result.deleted_count == 0:
        return err("Anomaly flag not found", code=404)
    return jsonify({"message": "Anomaly flag deleted"}), 200


@user_bp.route("/anomaly-flags/<string:id>/resolve", methods=["POST"])
@analyst_or_admin
def add_resolution_log(id):
    data = request.get_json() or {}
    note = data.get("note", "").strip()

    if not note:
        return err("note is required", "note")

    action = data.get("action_taken", "no_action")
    if action not in {"whitelisted", "suspended", "password_reset", "mfa_enforced", "no_action", "escalated"}:
        return err("Invalid action_taken value", "action_taken", 422)

    resolution = {
        "_id":          ObjectId(),
        "admin_email":  data.get("admin_email", ""),
        "note":         note,
        "action_taken": action,
        "timestamp":    datetime.utcnow().isoformat(),
    }

    result = anomaly_flags_col.update_one(
        build_id_query(id),
        {
            "$push": {"resolution_logs": resolution},
            "$set":  {"resolved": True},
        },
    )
    if result.matched_count == 0:
        return err("Anomaly flag not found", code=404)

    return jsonify({"message": "Resolution log added", "resolution_id": str(resolution["_id"])}), 201


@user_bp.route("/anomaly-flags/<string:flag_id>/resolve/<string:res_id>", methods=["DELETE"])
@admin_required
def delete_resolution_log(flag_id, res_id):
    res_oid = ObjectId(res_id) if ObjectId.is_valid(res_id) else res_id
    result  = anomaly_flags_col.update_one(
        build_id_query(flag_id),
        {"$pull": {"resolution_logs": {"_id": res_oid}}},
    )
    if result.matched_count == 0:
        return err("Anomaly flag not found", code=404)
    return jsonify({"message": "Resolution log deleted"}), 200