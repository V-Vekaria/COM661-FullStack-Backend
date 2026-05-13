from flask import Blueprint, request, jsonify
from config import get_db
from middleware.auth_middleware import require_admin_or_analyst
from bson import ObjectId
import datetime

analytics_bp = Blueprint("analytics", __name__)

VALID_REGIONS  = {"eu-west", "us-east", "us-west", "ap-south", "ap-northeast", "sa-east", "af-south"}
VALID_ACTIONS  = {
    "login", "logout", "upload", "download", "delete", "create", "update",
    "export", "failed_login", "password_reset", "api_key_generate",
    "billing_view", "report_generate", "settings_update",
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


@analytics_bp.route("/dashboard/summary", methods=["GET"])
@require_admin_or_analyst
def dashboard_summary():
    db = get_db()

    total_users  = db["users"].count_documents({})
    active_users = db["users"].count_documents({"subscription.status": "active"})
    total_logs   = db["activity_logs"].count_documents({})
    open_anomalies = db["anomaly_flags"].count_documents({"resolved": False})

    return jsonify({
        "total_users":     total_users,
        "active_users":    active_users,
        "total_logs":      total_logs,
        "open_anomalies":  open_anomalies,
    }), 200


@analytics_bp.route("/analytics/avg-api-calls", methods=["GET"])
@require_admin_or_analyst
def avg_api_calls():
    """Average API calls per user — uses $unwind + $group aggregation."""
    db = get_db()

    pipeline = [
        {"$unwind": "$usage_logs"},
        {"$group": {
            "_id":          "$_id",
            "email":        {"$first": "$profile.email"},
            "avg_api_calls": {"$avg": "$usage_logs.metrics.api_calls"},
        }},
        {"$project": {
            "_id":           {"$toString": "$_id"},
            "email":         1,
            "avg_api_calls": {"$round": ["$avg_api_calls", 2]},
        }},
    ]

    results = list(db["users"].aggregate(pipeline))
    return jsonify(results), 200


@analytics_bp.route("/analytics/avg-api-calls-by-tier", methods=["GET"])
@require_admin_or_analyst
def avg_api_calls_by_tier():
    """Average API calls grouped by subscription tier."""
    db = get_db()

    pipeline = [
        {"$unwind": "$usage_logs"},
        {"$group": {
            "_id":           "$subscription.tier",
            "avg_api_calls": {"$avg": "$usage_logs.metrics.api_calls"},
            "user_count":    {"$addToSet": "$_id"},
        }},
        {"$project": {
            "tier":          "$_id",
            "avg_api_calls": {"$round": ["$avg_api_calls", 2]},
            "user_count":    {"$size": "$user_count"},
            "_id":           0,
        }},
    ]

    results = list(db["users"].aggregate(pipeline))
    return jsonify(results), 200


@analytics_bp.route("/analytics/high-usage", methods=["GET"])
@require_admin_or_analyst
def high_usage():
    """Users with any usage log exceeding the threshold."""
    threshold = request.args.get("threshold", 50000)

    try:
        threshold = int(threshold)
    except (ValueError, TypeError):
        return jsonify({"error": "threshold must be an integer", "field": "threshold"}), 422

    if threshold <= 0:
        return jsonify({"error": "threshold must be > 0", "field": "threshold"}), 422

    db = get_db()

    pipeline = [
        {"$unwind": "$usage_logs"},
        {"$match": {"usage_logs.metrics.api_calls": {"$gt": threshold}}},
        {"$group": {
            "_id":       "$_id",
            "email":     {"$first": "$profile.email"},
            "max_calls": {"$max": "$usage_logs.metrics.api_calls"},
        }},
        {"$project": {
            "_id":       {"$toString": "$_id"},
            "email":     1,
            "max_calls": 1,
        }},
    ]

    results = list(db["users"].aggregate(pipeline))
    return jsonify({"results": results, "threshold": threshold}), 200


@analytics_bp.route("/analytics/failed-logins", methods=["GET"])
@require_admin_or_analyst
def failed_logins():
    """Users with failed login count above threshold in activity_logs."""
    threshold = request.args.get("threshold", 3)

    try:
        threshold = int(threshold)
    except (ValueError, TypeError):
        return jsonify({"error": "threshold must be an integer", "field": "threshold"}), 422

    if threshold <= 0:
        return jsonify({"error": "threshold must be > 0", "field": "threshold"}), 422

    db = get_db()

    pipeline = [
        {"$match": {"action_type": "failed_login"}},
        {"$group": {
            "_id":          "$user_id",
            "user_email":   {"$first": "$user_email"},
            "failed_count": {"$sum": 1},
        }},
        {"$match": {"failed_count": {"$gte": threshold}}},
        {"$project": {
            "_id":          0,
            "user_id":      "$_id",
            "user_email":   1,
            "failed_count": 1,
        }},
    ]

    results = list(db["activity_logs"].aggregate(pipeline))
    return jsonify({"flagged_users": results, "threshold": threshold}), 200


@analytics_bp.route("/analytics/anomaly-summary", methods=["GET"])
@require_admin_or_analyst
def anomaly_summary():
    """Anomaly count grouped by severity."""
    db = get_db()

    pipeline = [
        {"$group": {
            "_id":   "$severity",
            "count": {"$sum": 1},
        }},
        {"$project": {
            "severity": "$_id",
            "count":    1,
            "_id":      0,
        }},
    ]

    results = list(db["anomaly_flags"].aggregate(pipeline))
    return jsonify(results), 200


@analytics_bp.route("/analytics/search-logs", methods=["GET"])
@require_admin_or_analyst
def search_logs():
    """Search activity logs with multiple filters + pagination."""
    db = get_db()
    query = {}

    action_types = request.args.get("action_types")
    regions      = request.args.get("regions")
    status_code  = request.args.get("status_code")

    if action_types:
        query["action_type"] = {"$in": action_types.split(",")}
    if regions:
        query["network.region"] = {"$in": regions.split(",")}
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


@analytics_bp.route("/analytics/nearby-activity", methods=["GET"])
@require_admin_or_analyst
def nearby_activity():
    """Geospatial query — find activity logs near a coordinate."""
    lat          = request.args.get("lat")
    lng          = request.args.get("lng")
    max_distance = request.args.get("max_distance", 100000)

    if lat is None or lng is None:
        return jsonify({"error": "lat and lng required"}), 400

    try:
        lat = float(lat)
        lng = float(lng)
        max_distance = float(max_distance)
    except ValueError:
        return jsonify({"error": "lat, lng, max_distance must be numbers"}), 422

    if not (-90 <= lat <= 90):
        return jsonify({"error": "lat must be -90 to 90", "field": "lat"}), 422
    if not (-180 <= lng <= 180):
        return jsonify({"error": "lng must be -180 to 180", "field": "lng"}), 422
    if max_distance <= 0:
        return jsonify({"error": "max_distance must be > 0", "field": "max_distance"}), 422

    db = get_db()

    # Ensure 2dsphere index exists
    db["activity_logs"].create_index([("network.location", "2dsphere")], background=True)

    results = list(db["activity_logs"].find({
        "network.location": {
            "$nearSphere": {
                "$geometry":    {"type": "Point", "coordinates": [lng, lat]},
                "$maxDistance": max_distance,
            }
        }
    }).limit(50))

    return jsonify({"count": len(results), "results": to_json(results)}), 200


@analytics_bp.route("/analytics/user-risk-report", methods=["GET"])
@require_admin_or_analyst
def user_risk_report():
    """Cross-collection $lookup — join users with their anomaly flags."""
    db = get_db()

    pipeline = [
        {"$lookup": {
            "from":         "anomaly_flags",
            "localField":   "_id",
            "foreignField": "user_id",
            "as":           "anomalies",
            "let":          {"uid": {"$toString": "$_id"}},
            "pipeline": [
                {"$match": {"$expr": {"$eq": ["$user_id", "$$uid"]}}},
            ],
        }},
        {"$project": {
            "_id":            {"$toString": "$_id"},
            "email":          "$profile.email",
            "churn_risk":     "$metadata.churn_risk",
            "tier":           "$subscription.tier",
            "anomaly_count":  {"$size": "$anomalies"},
            "open_anomalies": {
                "$size": {
                    "$filter": {
                        "input": "$anomalies",
                        "cond":  {"$eq": ["$$this.resolved", False]},
                    }
                }
            },
        }},
    ]

    results = list(db["users"].aggregate(pipeline))
    return jsonify(results), 200


@analytics_bp.route("/analytics/ops-breakdown", methods=["GET"])
@require_admin_or_analyst
def ops_breakdown():
    """Level-4 nesting query — breakdown of usage metrics by subscription tier."""
    db = get_db()

    pipeline = [
        {"$unwind": "$usage_logs"},
        {"$group": {
            "_id":           "$subscription.tier",
            "total_calls":   {"$sum": "$usage_logs.metrics.api_calls"},
            "total_reads":   {"$sum": "$usage_logs.metrics.breakdown.reads"},
            "total_writes":  {"$sum": "$usage_logs.metrics.breakdown.writes"},
            "avg_storage":   {"$avg": "$usage_logs.metrics.storage_mb"},
            "user_count":    {"$addToSet": "$_id"},
        }},
        {"$project": {
            "tier":         "$_id",
            "total_calls":  1,
            "total_reads":  1,
            "total_writes": 1,
            "avg_storage":  {"$round": ["$avg_storage", 2]},
            "user_count":   {"$size": "$user_count"},
            "_id":          0,
        }},
    ]

    results = list(db["users"].aggregate(pipeline))
    return jsonify(results), 200