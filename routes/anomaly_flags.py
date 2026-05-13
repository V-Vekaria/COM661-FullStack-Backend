from flask import Blueprint, request, jsonify
from config import get_db
from middleware.auth_middleware import require_auth, require_admin, require_admin_or_analyst
from bson import ObjectId
import datetime

anomaly_bp = Blueprint("anomaly", __name__)

VALID_SEVERITY   = {"low", "medium", "high", "critical"}
VALID_CATEGORIES = {"security", "performance", "billing", "compliance"}
VALID_ACTIONS    = {"whitelisted", "suspended", "password_reset", "mfa_enforced", "no_action", "escalated"}


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


@anomaly_bp.route("/anomaly-flags", methods=["POST"])
@require_admin
def create_flag():
    body = request.get_json(silent=True) or {}
    db = get_db()

    if "user_id" not in body:
        return jsonify({"error": "user_id required", "field": "user_id"}), 400
    if "reason" not in body:
        return jsonify({"error": "reason required", "field": "reason"}), 400

    if "anomaly_score" in body:
        score = body["anomaly_score"]
        if not isinstance(score, (int, float)) or isinstance(score, bool):
            return jsonify({"error": "anomaly_score must be a number", "field": "anomaly_score"}), 422
        if not (0.0 <= score <= 1.0):
            return jsonify({"error": "anomaly_score must be 0.0-1.0", "field": "anomaly_score"}), 422

    if "severity" in body and body["severity"] not in VALID_SEVERITY:
        return jsonify({"error": "Invalid severity", "field": "severity"}), 422

    if "category" in body and body["category"] not in VALID_CATEGORIES:
        return jsonify({"error": "Invalid category", "field": "category"}), 422

    doc = {
        "user_id":       body["user_id"],
        "user_email":    body.get("user_email", ""),
        "reason":        body["reason"],
        "anomaly_score": body.get("anomaly_score", 0.5),
        "severity":      body.get("severity", "medium"),
        "category":      body.get("category", "security"),
        "detected_at":   datetime.datetime.utcnow(),
        "resolved":      False,
        "resolution_logs": [],
        "evidence": body.get("evidence", {}),
    }

    result = db["anomaly_flags"].insert_one(doc)
    return jsonify({"flag_id": str(result.inserted_id)}), 201


@anomaly_bp.route("/anomaly-flags", methods=["GET"])
@require_admin_or_analyst
def list_flags():
    db = get_db()
    query = {}

    severity = request.args.get("severity")
    resolved = request.args.get("resolved")
    category = request.args.get("category")

    if severity:
        if severity not in VALID_SEVERITY:
            return jsonify({"error": "Invalid severity filter", "field": "severity"}), 422
        query["severity"] = severity

    if resolved is not None:
        query["resolved"] = resolved.lower() == "true"

    if category:
        query["category"] = category

    pn = int(request.args.get("pn", 1))
    ps = int(request.args.get("ps", 10))
    skip = (pn - 1) * ps

    total = db["anomaly_flags"].count_documents(query)
    flags = list(db["anomaly_flags"].find(query).skip(skip).limit(ps))

    return jsonify({"flags": to_json(flags), "total": total}), 200


@anomaly_bp.route("/anomaly-flags/<string:flag_id>", methods=["GET"])
@require_admin_or_analyst
def get_flag(flag_id):
    db = get_db()
    try:
        oid = ObjectId(flag_id)
    except Exception:
        return jsonify({"error": "Invalid flag ID"}), 400

    flag = db["anomaly_flags"].find_one({"_id": oid})
    if not flag:
        return jsonify({"error": "Flag not found"}), 404

    return jsonify(to_json(flag)), 200


@anomaly_bp.route("/anomaly-flags/<string:flag_id>", methods=["PUT"])
@require_admin
def update_flag(flag_id):
    body = request.get_json(silent=True) or {}
    if not body:
        return jsonify({"error": "Request body required"}), 400

    db = get_db()
    try:
        oid = ObjectId(flag_id)
    except Exception:
        return jsonify({"error": "Invalid flag ID"}), 400

    updates = {}

    if "severity" in body:
        if body["severity"] not in VALID_SEVERITY:
            return jsonify({"error": "Invalid severity", "field": "severity"}), 422
        updates["severity"] = body["severity"]

    if "anomaly_score" in body:
        score = body["anomaly_score"]
        if not isinstance(score, (int, float)) or isinstance(score, bool):
            return jsonify({"error": "anomaly_score must be a number", "field": "anomaly_score"}), 422
        if not (0.0 <= score <= 1.0):
            return jsonify({"error": "anomaly_score must be 0.0-1.0", "field": "anomaly_score"}), 422
        updates["anomaly_score"] = score

    if "resolved" in body:
        updates["resolved"] = bool(body["resolved"])

    if not updates:
        return jsonify({"error": "No valid fields"}), 400

    result = db["anomaly_flags"].update_one({"_id": oid}, {"$set": updates})
    if result.matched_count == 0:
        return jsonify({"error": "Flag not found"}), 404

    return jsonify({"message": "Flag updated"}), 200


@anomaly_bp.route("/anomaly-flags/<string:flag_id>", methods=["DELETE"])
@require_admin
def delete_flag(flag_id):
    db = get_db()
    try:
        oid = ObjectId(flag_id)
    except Exception:
        return jsonify({"error": "Invalid flag ID"}), 400

    result = db["anomaly_flags"].delete_one({"_id": oid})
    if result.deleted_count == 0:
        return jsonify({"error": "Flag not found"}), 404

    return jsonify({"message": "Flag deleted"}), 200


# ---------------------------------------------------------------------------
# RESOLUTION LOGS  (embedded in anomaly_flags)
# ---------------------------------------------------------------------------

@anomaly_bp.route("/anomaly-flags/<string:flag_id>/resolve", methods=["POST"])
@require_admin_or_analyst
def add_resolution(flag_id):
    body = request.get_json(silent=True) or {}
    db = get_db()

    try:
        oid = ObjectId(flag_id)
    except Exception:
        return jsonify({"error": "Invalid flag ID"}), 400

    if "note" not in body:
        return jsonify({"error": "note required", "field": "note"}), 400

    if "action_taken" in body and body["action_taken"] not in VALID_ACTIONS:
        return jsonify({"error": "Invalid action_taken", "field": "action_taken"}), 422

    if not db["anomaly_flags"].find_one({"_id": oid}):
        return jsonify({"error": "Flag not found"}), 404

    resolution_id = ObjectId()
    resolution = {
        "_id":          resolution_id,
        "note":         body["note"],
        "action_taken": body.get("action_taken", "no_action"),
        "admin_email":  body.get("admin_email", ""),
        "timestamp":    datetime.datetime.utcnow(),
    }

    db["anomaly_flags"].update_one(
        {"_id": oid},
        {
            "$push": {"resolution_logs": resolution},
            "$set":  {"resolved": True},
        }
    )
    return jsonify({"resolution_id": str(resolution_id)}), 201


@anomaly_bp.route("/anomaly-flags/<string:flag_id>/resolve/<string:resolution_id>", methods=["DELETE"])
@require_admin
def delete_resolution(flag_id, resolution_id):
    db = get_db()
    try:
        f_oid = ObjectId(flag_id)
        r_oid = ObjectId(resolution_id)
    except Exception:
        return jsonify({"error": "Invalid ID"}), 400

    flag = db["anomaly_flags"].find_one({"_id": f_oid, "resolution_logs._id": r_oid})
    if not flag:
        return jsonify({"error": "Resolution not found"}), 404

    db["anomaly_flags"].update_one(
        {"_id": f_oid},
        {"$pull": {"resolution_logs": {"_id": r_oid}}}
    )
    return jsonify({"message": "Resolution deleted"}), 200