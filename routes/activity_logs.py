from flask import Blueprint, request, jsonify
from config import get_db
from middleware.auth_middleware import require_auth, require_admin, require_admin_or_analyst
from bson import ObjectId
import datetime

activity_bp = Blueprint("activity", __name__)

VALID_REGIONS  = {"eu-west", "us-east", "us-west", "ap-south", "ap-northeast", "sa-east", "af-south"}
VALID_ACTIONS  = {
    "login", "logout", "upload", "download", "delete", "create", "update",
    "export", "failed_login", "password_reset", "api_key_generate",
    "billing_view", "report_generate", "settings_update",
}
REGION_COORDS = {
    "eu-west":      {"type": "Point", "coordinates": [-0.1278,    51.5074]},
    "us-east":      {"type": "Point", "coordinates": [-77.0369,   38.9072]},
    "us-west":      {"type": "Point", "coordinates": [-122.4194,  37.7749]},
    "ap-south":     {"type": "Point", "coordinates": [72.8777,    19.0760]},
    "ap-northeast": {"type": "Point", "coordinates": [139.6917,   35.6895]},
    "sa-east":      {"type": "Point", "coordinates": [-46.6333,  -23.5505]},
    "af-south":     {"type": "Point", "coordinates": [18.4241,   -33.9249]},
}


def to_json(doc):
    if isinstance(doc, list):
        return [to_json(d) for d in doc]
    if isinstance(doc, dict):
        return {k: to_json(v) for k, v in doc.items()}
    if isinstance(doc, ObjectId):
        return str(doc)
    if isinstance(doc, datetime.datetime):
        return doc.isoformat()
    return doc


@activity_bp.route("/activity-logs", methods=["POST"])
@require_admin_or_analyst
def create_log():
    body = request.get_json(silent=True) or {}
    db = get_db()

    if "user_id" not in body:
        return jsonify({"error": "user_id required", "field": "user_id"}), 400
    if "action_type" not in body:
        return jsonify({"error": "action_type required", "field": "action_type"}), 400

    # Validate status_code range 100-599
    if "status_code" in body:
        sc = body["status_code"]
        if not isinstance(sc, int) or isinstance(sc, bool):
            return jsonify({"error": "status_code must be an integer", "field": "status_code"}), 422
        if not (100 <= sc <= 599):
            return jsonify({"error": "status_code must be 100-599", "field": "status_code"}), 422

    if "region" in body and body["region"] not in VALID_REGIONS:
        return jsonify({"error": "Invalid region", "field": "region"}), 422

    if "response_time_ms" in body:
        rt = body["response_time_ms"]
        if not isinstance(rt, (int, float)) or isinstance(rt, bool) or rt < 0:
            return jsonify({"error": "response_time_ms must be >= 0", "field": "response_time_ms"}), 422

    region = body.get("region", "eu-west")
    doc = {
        "user_id":     body["user_id"],
        "user_email":  body.get("user_email", ""),
        "action_type": body["action_type"],
        "network": {
            "region":           region,
            "location":         REGION_COORDS.get(region),
            "ip_address":       body.get("ip_address", "0.0.0.0"),
            "device_type":      body.get("device_type", "desktop"),
        },
        "performance": {
            "status_code":      body.get("status_code", 200),
            "response_time_ms": body.get("response_time_ms", 0),
        },
        "timestamp":  datetime.datetime.utcnow(),
        "session_id": body.get("session_id", ""),
    }

    result = db["activity_logs"].insert_one(doc)
    return jsonify({"log_id": str(result.inserted_id)}), 201


@activity_bp.route("/activity-logs", methods=["GET"])
@require_admin_or_analyst
def list_logs():
    db = get_db()
    query = {}

    action_type = request.args.get("action_type")
    region      = request.args.get("region")
    status_code = request.args.get("status_code")

    if action_type:
        query["action_type"] = action_type
    if region:
        query["network.region"] = region
    if status_code:
        if not status_code.isdigit():
            return jsonify({"error": "status_code must be an integer", "field": "status_code"}), 422
        query["performance.status_code"] = int(status_code)

    pn = int(request.args.get("pn", 1))
    ps = int(request.args.get("ps", 10))
    skip = (pn - 1) * ps

    total = db["activity_logs"].count_documents(query)
    logs  = list(db["activity_logs"].find(query).skip(skip).limit(ps))

    return jsonify({"logs": to_json(logs), "total": total}), 200


@activity_bp.route("/activity-logs/<string:log_id>", methods=["GET"])
@require_admin_or_analyst
def get_log(log_id):
    db = get_db()
    try:
        oid = ObjectId(log_id)
    except Exception:
        return jsonify({"error": "Invalid log ID"}), 400

    log = db["activity_logs"].find_one({"_id": oid})
    if not log:
        return jsonify({"error": "Log not found"}), 404

    return jsonify(to_json(log)), 200


@activity_bp.route("/activity-logs/<string:log_id>", methods=["PUT"])
@require_admin
def update_log(log_id):
    body = request.get_json(silent=True) or {}
    if not body:
        return jsonify({"error": "Request body required"}), 400

    db = get_db()
    try:
        oid = ObjectId(log_id)
    except Exception:
        return jsonify({"error": "Invalid log ID"}), 400

    updates = {}

    if "status_code" in body:
        sc = body["status_code"]
        if not isinstance(sc, int) or isinstance(sc, bool):
            return jsonify({"error": "status_code must be an integer", "field": "status_code"}), 422
        if not (100 <= sc <= 599):
            return jsonify({"error": "status_code out of range", "field": "status_code"}), 422
        updates["performance.status_code"] = sc

    if "action_type" in body:
        updates["action_type"] = body["action_type"]

    if not updates:
        return jsonify({"error": "No valid fields"}), 400

    result = db["activity_logs"].update_one({"_id": oid}, {"$set": updates})
    if result.matched_count == 0:
        return jsonify({"error": "Log not found"}), 404

    return jsonify({"message": "Log updated"}), 200


@activity_bp.route("/activity-logs/<string:log_id>", methods=["DELETE"])
@require_admin
def delete_log(log_id):
    db = get_db()
    try:
        oid = ObjectId(log_id)
    except Exception:
        return jsonify({"error": "Invalid log ID"}), 400

    result = db["activity_logs"].delete_one({"_id": oid})
    if result.deleted_count == 0:
        return jsonify({"error": "Log not found"}), 404

    return jsonify({"message": "Log deleted"}), 200