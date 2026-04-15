from flask import Blueprint, request, jsonify
from config import db
from bson import ObjectId
from datetime import datetime
from auth import basic_auth_required, admin_required
import bcrypt
import random
import string

user_bp = Blueprint("users", __name__)

users_col = db["users"]
login_col = db["login"]
activity_logs_col = db["activity_logs"]
anomaly_flags_col = db["anomaly_flags"]

REGION_COORDS = {
    "eu-west":      {"type": "Point", "coordinates": [-0.1278, 51.5074]},
    "us-east":      {"type": "Point", "coordinates": [-77.0369, 38.9072]},
    "us-west":      {"type": "Point", "coordinates": [-122.4194, 37.7749]},
    "ap-south":     {"type": "Point", "coordinates": [72.8777, 19.0760]},
    "ap-northeast": {"type": "Point", "coordinates": [139.6917, 35.6895]},
    "sa-east":      {"type": "Point", "coordinates": [-46.6333, -23.5505]},
    "af-south":     {"type": "Point", "coordinates": [18.4241, -33.9249]}
}


def build_id_query(id):
    if ObjectId.is_valid(id):
        return {"_id": ObjectId(id)}
    return {"_id": id}


def serialize_doc(doc):
    if isinstance(doc, list):
        return [serialize_doc(d) for d in doc]
    if isinstance(doc, dict):
        return {k: serialize_doc(v) for k, v in doc.items()}
    if isinstance(doc, ObjectId):
        return str(doc)
    return doc


# --- USERS ---

@user_bp.route("/users", methods=["POST"])
@admin_required
def create_user():
    email = request.form.get("email")
    password = request.form.get("password")
    role = request.form.get("role", "user")
    tier = request.form.get("subscription_tier", "free")
    first_name = request.form.get("first_name", "")
    last_name = request.form.get("last_name", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if users_col.find_one({"profile.email": email}):
        return jsonify({"error": "Email already exists"}), 409

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user_id = ObjectId()

    user_doc = {
        "_id": user_id,
        "profile": {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "role": role,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None
        },
        "subscription": {
            "tier": tier,
            "status": "active",
            "features_enabled": {
                "sso": tier == "enterprise",
                "advanced_analytics": tier in ["pro", "enterprise"],
                "priority_support": tier in ["pro", "enterprise"],
                "audit_logs": tier == "enterprise",
                "custom_domains": tier == "enterprise"
            }
        },
        "usage_logs": [],
        "api_keys": [],
        "alerts": [],
        "metadata": {}
    }

    login_doc = {
        "email": email,
        "password": hashed,
        "role": role,
        "user_id": str(user_id),
        "failed_attempts": 0,
        "sessions": []
    }

    users_col.insert_one(user_doc)
    login_col.insert_one(login_doc)

    return jsonify({"message": "User created", "user_id": str(user_id)}), 201


@user_bp.route("/users", methods=["GET"])
@admin_required
def get_users():
    page_num = int(request.args.get("pn", 1))
    page_size = int(request.args.get("ps", 10))
    skip = (page_num - 1) * page_size

    query = {}
    if request.args.get("role"):
        query["profile.role"] = request.args.get("role")
    if request.args.get("tier"):
        query["subscription.tier"] = request.args.get("tier")
    if request.args.get("status"):
        query["subscription.status"] = request.args.get("status")

    # only return profile in list view, use GET /users/<id> for full detail
    projection = {
        "profile": 1
    }

    total = users_col.count_documents(query)
    users = list(users_col.find(query, projection).skip(skip).limit(page_size))

    return jsonify({"total": total, "page": page_num, "per_page": page_size, "users": serialize_doc(users)}), 200


@user_bp.route("/users/<string:id>", methods=["GET"])
@basic_auth_required
def get_one_user(id):
    user = users_col.find_one(build_id_query(id))
    if user is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify(serialize_doc(user)), 200


@user_bp.route("/users/<string:id>", methods=["PUT"])
@basic_auth_required
def update_user(id):
    fields = {}

    if request.form.get("email"):
        fields["profile.email"] = request.form.get("email")
    if request.form.get("first_name"):
        fields["profile.first_name"] = request.form.get("first_name")
    if request.form.get("last_name"):
        fields["profile.last_name"] = request.form.get("last_name")
    if request.form.get("subscription_tier"):
        fields["subscription.tier"] = request.form.get("subscription_tier")
    if request.form.get("account_status"):
        fields["subscription.status"] = request.form.get("account_status")

    if not fields:
        return jsonify({"error": "No fields provided to update"}), 400

    result = users_col.update_one(build_id_query(id), {"$set": fields})
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User updated"}), 200


@user_bp.route("/users/<string:id>", methods=["DELETE"])
@admin_required
def delete_user(id):
    result = users_col.delete_one(build_id_query(id))
    if result.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404

    login_col.delete_one({"user_id": id})
    return jsonify({"message": "User deleted"}), 200


@user_bp.route("/users/search", methods=["GET"])
@admin_required
def search_users():
    query = {}

    if request.args.get("email"):
        query["profile.email"] = {"$regex": request.args.get("email"), "$options": "i"}
    if request.args.get("role"):
        query["profile.role"] = request.args.get("role")
    if request.args.get("tier"):
        query["subscription.tier"] = {"$in": request.args.get("tier").split(",")}
    if request.args.get("status"):
        query["subscription.status"] = request.args.get("status")
    if request.args.get("churn_risk"):
        query["metadata.churn_risk"] = request.args.get("churn_risk")

    projection = {
        "profile": 1,
        "subscription.tier": 1,
        "subscription.status": 1,
        "metadata.churn_risk": 1
    }

    users = list(users_col.find(query, projection))
    return jsonify({"count": len(users), "users": serialize_doc(users)}), 200


# --- USAGE LOGS (sub-documents) ---

@user_bp.route("/users/<string:id>/usage", methods=["POST"])
@admin_required
def add_usage_log(id):
    api_calls = request.form.get("api_calls")
    storage_mb = request.form.get("storage_mb")
    region = request.form.get("region", "eu-west")
    endpoint = request.form.get("endpoint", "/api/upload")
    method = request.form.get("method", "POST")

    if not api_calls or not storage_mb:
        return jsonify({"error": "api_calls and storage_mb are required"}), 400

    log = {
        "_id": ObjectId(),
        "timestamp": datetime.utcnow().isoformat(),
        "metrics": {
            "api_calls": int(api_calls),
            "storage_mb": float(storage_mb)
        },
        "request": {
            "endpoint": endpoint,
            "region": region,
            "method": method,
            "status_code": 200
        },
        "location": REGION_COORDS.get(region, REGION_COORDS["eu-west"])
    }

    result = users_col.update_one(build_id_query(id), {"$push": {"usage_logs": log}})
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "Usage log added", "log_id": str(log["_id"])}), 201


@user_bp.route("/users/<string:id>/usage", methods=["GET"])
@basic_auth_required
def get_usage_logs(id):
    user = users_col.find_one(build_id_query(id))
    if user is None:
        return jsonify({"error": "User not found"}), 404
    logs = user.get("usage_logs", [])
    for log in logs:
        if isinstance(log.get("_id"), ObjectId):
            log["_id"] = str(log["_id"])
    return jsonify(logs), 200


@user_bp.route("/users/<string:user_id>/usage/<string:log_id>", methods=["PUT"])
@admin_required
def update_usage_log(user_id, log_id):
    fields = {}

    if request.form.get("api_calls"):
        fields["usage_logs.$.metrics.api_calls"] = int(request.form.get("api_calls"))
    if request.form.get("storage_mb"):
        fields["usage_logs.$.metrics.storage_mb"] = float(request.form.get("storage_mb"))
    if request.form.get("endpoint"):
        fields["usage_logs.$.request.endpoint"] = request.form.get("endpoint")

    if not fields:
        return jsonify({"error": "No fields provided to update"}), 400

    log_oid = ObjectId(log_id) if ObjectId.is_valid(log_id) else log_id

    result = users_col.update_one(
        {**build_id_query(user_id), "usage_logs._id": log_oid},
        {"$set": fields}
    )
    if result.matched_count == 0:
        return jsonify({"error": "User or usage log not found"}), 404

    return jsonify({"message": "Usage log updated"}), 200


@user_bp.route("/users/<string:user_id>/usage/<string:log_id>", methods=["DELETE"])
@admin_required
def delete_usage_log(user_id, log_id):
    log_oid = ObjectId(log_id) if ObjectId.is_valid(log_id) else log_id

    result = users_col.update_one(
        build_id_query(user_id),
        {"$pull": {"usage_logs": {"_id": log_oid}}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "Usage log deleted"}), 200


# --- API KEYS (sub-documents) ---

@user_bp.route("/users/<string:id>/api-keys", methods=["POST"])
@basic_auth_required
def add_api_key(id):
    user = users_col.find_one(build_id_query(id))
    if user is None:
        return jsonify({"error": "User not found"}), 404

    tier = user.get("subscription", {}).get("tier", "free")
    permissions = request.form.getlist("permissions") or ["read"]
    env = "live" if tier != "free" else "test"
    rand_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

    key = {
        "_id": ObjectId(),
        "key_prefix": "sk_" + env + "_" + rand_suffix,
        "created_at": datetime.utcnow().isoformat(),
        "last_used": None,
        "revoked": False,
        "permissions": permissions
    }

    users_col.update_one(build_id_query(id), {"$push": {"api_keys": key}})
    return jsonify({"message": "API key created", "key_id": str(key["_id"]), "key_prefix": key["key_prefix"]}), 201


@user_bp.route("/users/<string:id>/api-keys", methods=["GET"])
@basic_auth_required
def get_api_keys(id):
    user = users_col.find_one(build_id_query(id))
    if user is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify(serialize_doc(user.get("api_keys", []))), 200


@user_bp.route("/users/<string:user_id>/api-keys/<string:key_id>/revoke", methods=["PUT"])
@basic_auth_required
def revoke_api_key(user_id, key_id):
    key_oid = ObjectId(key_id) if ObjectId.is_valid(key_id) else key_id

    result = users_col.update_one(
        {**build_id_query(user_id), "api_keys._id": key_oid},
        {"$set": {"api_keys.$.revoked": True}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "User or API key not found"}), 404

    return jsonify({"message": "API key revoked"}), 200


@user_bp.route("/users/<string:user_id>/api-keys/<string:key_id>", methods=["DELETE"])
@basic_auth_required
def delete_api_key(user_id, key_id):
    key_oid = ObjectId(key_id) if ObjectId.is_valid(key_id) else key_id

    result = users_col.update_one(
        build_id_query(user_id),
        {"$pull": {"api_keys": {"_id": key_oid}}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "API key deleted"}), 200


# --- ALERTS (sub-documents) ---

@user_bp.route("/users/<string:id>/alerts", methods=["POST"])
@admin_required
def add_alert(id):
    message = request.form.get("message")
    if not message:
        return jsonify({"error": "message is required"}), 400

    alert = {
        "_id": ObjectId(),
        "alert_type": request.form.get("alert_type", "threshold_breach"),
        "message": message,
        "severity": request.form.get("severity", "medium"),
        "triggered_at": datetime.utcnow().isoformat(),
        "acknowledged": False
    }

    result = users_col.update_one(build_id_query(id), {"$push": {"alerts": alert}})
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "Alert added", "alert_id": str(alert["_id"])}), 201


@user_bp.route("/users/<string:id>/alerts", methods=["GET"])
@basic_auth_required
def get_alerts(id):
    user = users_col.find_one(build_id_query(id))
    if user is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify(serialize_doc(user.get("alerts", []))), 200


@user_bp.route("/users/<string:user_id>/alerts/<string:alert_id>/acknowledge", methods=["PUT"])
@basic_auth_required
def acknowledge_alert(user_id, alert_id):
    alert_oid = ObjectId(alert_id) if ObjectId.is_valid(alert_id) else alert_id

    result = users_col.update_one(
        {**build_id_query(user_id), "alerts._id": alert_oid},
        {"$set": {"alerts.$.acknowledged": True}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "User or alert not found"}), 404

    return jsonify({"message": "Alert acknowledged"}), 200


@user_bp.route("/users/<string:user_id>/alerts/<string:alert_id>", methods=["DELETE"])
@admin_required
def delete_alert(user_id, alert_id):
    alert_oid = ObjectId(alert_id) if ObjectId.is_valid(alert_id) else alert_id

    result = users_col.update_one(
        build_id_query(user_id),
        {"$pull": {"alerts": {"_id": alert_oid}}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "Alert deleted"}), 200


# --- ACTIVITY LOGS ---

@user_bp.route("/activity-logs", methods=["POST"])
@admin_required
def create_activity_log():
    user_id = request.form.get("user_id")
    action_type = request.form.get("action_type")

    if not user_id or not action_type:
        return jsonify({"error": "user_id and action_type are required"}), 400

    region = request.form.get("region", "eu-west")

    log = {
        "user_id": ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id,
        "user_email": request.form.get("user_email", ""),
        "action_type": action_type,
        "resource": {
            "id": request.form.get("resource_id", ""),
            "type": request.form.get("resource_type", "file"),
            "name": request.form.get("resource_name", "")
        },
        "network": {
            "ip_address": request.form.get("ip_address", "0.0.0.0"),
            "device_type": request.form.get("device_type", "desktop"),
            "region": region,
            "location": REGION_COORDS.get(region, REGION_COORDS["eu-west"])
        },
        "performance": {
            "response_time_ms": int(request.form.get("response_time_ms", 200)),
            "status_code": int(request.form.get("status_code", 200)),
            "bytes_transferred": int(request.form.get("bytes_transferred", 0))
        },
        "timestamp": datetime.utcnow().isoformat(),
        "session_id": request.form.get("session_id", "")
    }

    result = activity_logs_col.insert_one(log)
    return jsonify({"message": "Activity log created", "log_id": str(result.inserted_id)}), 201


@user_bp.route("/activity-logs", methods=["GET"])
@admin_required
def get_activity_logs():
    page_num = int(request.args.get("pn", 1))
    page_size = int(request.args.get("ps", 10))
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
        query["performance.status_code"] = int(request.args.get("status_code"))

    date_filter = {}
    if request.args.get("from"):
        date_filter["$gte"] = request.args.get("from")
    if request.args.get("to"):
        date_filter["$lte"] = request.args.get("to")
    if date_filter:
        query["timestamp"] = date_filter

    total = activity_logs_col.count_documents(query)
    logs = list(activity_logs_col.find(query).sort("timestamp", -1).skip(skip).limit(page_size))

    return jsonify({"total": total, "page": page_num, "per_page": page_size, "logs": serialize_doc(logs)}), 200


@user_bp.route("/activity-logs/<string:id>", methods=["GET"])
@basic_auth_required
def get_activity_log(id):
    log = activity_logs_col.find_one(build_id_query(id))
    if log is None:
        return jsonify({"error": "Activity log not found"}), 404
    return jsonify(serialize_doc(log)), 200


@user_bp.route("/activity-logs/<string:id>", methods=["PUT"])
@admin_required
def update_activity_log(id):
    fields = {}
    if request.form.get("action_type"):
        fields["action_type"] = request.form.get("action_type")
    if request.form.get("status_code"):
        fields["performance.status_code"] = int(request.form.get("status_code"))
    if request.form.get("response_time_ms"):
        fields["performance.response_time_ms"] = int(request.form.get("response_time_ms"))

    if not fields:
        return jsonify({"error": "No fields provided to update"}), 400

    result = activity_logs_col.update_one(build_id_query(id), {"$set": fields})
    if result.matched_count == 0:
        return jsonify({"error": "Activity log not found"}), 404

    return jsonify({"message": "Activity log updated"}), 200


@user_bp.route("/activity-logs/<string:id>", methods=["DELETE"])
@admin_required
def delete_activity_log(id):
    result = activity_logs_col.delete_one(build_id_query(id))
    if result.deleted_count == 0:
        return jsonify({"error": "Activity log not found"}), 404
    return jsonify({"message": "Activity log deleted"}), 200


# --- ANOMALY FLAGS ---

@user_bp.route("/anomaly-flags", methods=["POST"])
@admin_required
def create_anomaly_flag():
    user_id = request.form.get("user_id")
    reason = request.form.get("reason")

    if not user_id or not reason:
        return jsonify({"error": "user_id and reason are required"}), 400

    flag = {
        "user_id": ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id,
        "user_email": request.form.get("user_email", ""),
        "reason": reason,
        "anomaly_score": float(request.form.get("anomaly_score", 0.5)),
        "severity": request.form.get("severity", "medium"),
        "category": request.form.get("category", "security"),
        "detected_at": datetime.utcnow().isoformat(),
        "resolved": False,
        "resolution_logs": [],
        "evidence": {
            "failed_login_count": int(request.form.get("failed_login_count", 0)),
            "suspicious_ips": request.form.getlist("suspicious_ips"),
            "time_window_hours": int(request.form.get("time_window_hours", 24))
        },
        "auto_actions_taken": {
            "account_locked": False,
            "notification_sent": True,
            "admin_alerted": True
        }
    }

    result = anomaly_flags_col.insert_one(flag)
    return jsonify({"message": "Anomaly flag created", "flag_id": str(result.inserted_id)}), 201


@user_bp.route("/anomaly-flags", methods=["GET"])
@admin_required
def get_anomaly_flags():
    page_num = int(request.args.get("pn", 1))
    page_size = int(request.args.get("ps", 10))
    skip = (page_num - 1) * page_size

    query = {}
    if request.args.get("severity"):
        query["severity"] = request.args.get("severity")
    if request.args.get("category"):
        query["category"] = request.args.get("category")
    if request.args.get("resolved"):
        query["resolved"] = request.args.get("resolved").lower() == "true"

    total = anomaly_flags_col.count_documents(query)
    flags = list(anomaly_flags_col.find(query).sort("detected_at", -1).skip(skip).limit(page_size))

    return jsonify({"total": total, "page": page_num, "per_page": page_size, "flags": serialize_doc(flags)}), 200


@user_bp.route("/anomaly-flags/<string:id>", methods=["GET"])
@admin_required
def get_anomaly_flag(id):
    flag = anomaly_flags_col.find_one(build_id_query(id))
    if flag is None:
        return jsonify({"error": "Anomaly flag not found"}), 404
    return jsonify(serialize_doc(flag)), 200


@user_bp.route("/anomaly-flags/<string:id>", methods=["PUT"])
@admin_required
def update_anomaly_flag(id):
    fields = {}
    if request.form.get("severity"):
        fields["severity"] = request.form.get("severity")
    if request.form.get("resolved"):
        fields["resolved"] = request.form.get("resolved").lower() == "true"
    if request.form.get("anomaly_score"):
        fields["anomaly_score"] = float(request.form.get("anomaly_score"))

    if not fields:
        return jsonify({"error": "No fields provided to update"}), 400

    result = anomaly_flags_col.update_one(build_id_query(id), {"$set": fields})
    if result.matched_count == 0:
        return jsonify({"error": "Anomaly flag not found"}), 404

    return jsonify({"message": "Anomaly flag updated"}), 200


@user_bp.route("/anomaly-flags/<string:id>", methods=["DELETE"])
@admin_required
def delete_anomaly_flag(id):
    result = anomaly_flags_col.delete_one(build_id_query(id))
    if result.deleted_count == 0:
        return jsonify({"error": "Anomaly flag not found"}), 404
    return jsonify({"message": "Anomaly flag deleted"}), 200


# resolution logs are sub-documents inside anomaly flags

@user_bp.route("/anomaly-flags/<string:id>/resolve", methods=["POST"])
@admin_required
def add_resolution_log(id):
    note = request.form.get("note")
    if not note:
        return jsonify({"error": "note is required"}), 400

    resolution = {
        "_id": ObjectId(),
        "admin_email": request.form.get("admin_email", ""),
        "note": note,
        "action_taken": request.form.get("action_taken", "no_action"),
        "timestamp": datetime.utcnow().isoformat()
    }

    result = anomaly_flags_col.update_one(
        build_id_query(id),
        {
            "$push": {"resolution_logs": resolution},
            "$set": {"resolved": True}
        }
    )
    if result.matched_count == 0:
        return jsonify({"error": "Anomaly flag not found"}), 404

    return jsonify({"message": "Resolution log added", "resolution_id": str(resolution["_id"])}), 201


@user_bp.route("/anomaly-flags/<string:flag_id>/resolve/<string:res_id>", methods=["DELETE"])
@admin_required
def delete_resolution_log(flag_id, res_id):
    res_oid = ObjectId(res_id) if ObjectId.is_valid(res_id) else res_id

    result = anomaly_flags_col.update_one(
        build_id_query(flag_id),
        {"$pull": {"resolution_logs": {"_id": res_oid}}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "Anomaly flag not found"}), 404

    return jsonify({"message": "Resolution log deleted"}), 200