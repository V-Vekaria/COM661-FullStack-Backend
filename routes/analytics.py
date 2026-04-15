from flask import Blueprint, request, jsonify
from config import db
from bson import ObjectId
from auth import admin_required

analytics_bp = Blueprint("analytics", __name__)

users_col = db["users"]
activity_logs_col = db["activity_logs"]
anomaly_flags_col = db["anomaly_flags"]


def serialize_doc(doc):
    if isinstance(doc, list):
        return [serialize_doc(d) for d in doc]
    if isinstance(doc, dict):
        return {k: serialize_doc(v) for k, v in doc.items()}
    if isinstance(doc, ObjectId):
        return str(doc)
    return doc


# average api calls per user
@analytics_bp.route("/analytics/avg-api-calls", methods=["GET"])
@admin_required
def avg_api_calls_per_user():
    pipeline = [
        {"$unwind": "$usage_logs"},
        {
            "$group": {
                "_id": "$_id",
                "email": {"$first": "$profile.email"},
                "subscription_tier": {"$first": "$subscription.tier"},
                "avg_api_calls": {"$avg": "$usage_logs.metrics.api_calls"},
                "total_api_calls": {"$sum": "$usage_logs.metrics.api_calls"}
            }
        },
        {"$sort": {"avg_api_calls": -1}}
    ]

    results = list(users_col.aggregate(pipeline))
    return jsonify(serialize_doc(results)), 200


# average api calls grouped by subscription tier
@analytics_bp.route("/analytics/avg-api-calls-by-tier", methods=["GET"])
@admin_required
def avg_api_calls_by_tier():
    pipeline = [
        {"$unwind": "$usage_logs"},
        {
            "$group": {
                "_id": "$subscription.tier",
                "avg_api_calls": {"$avg": "$usage_logs.metrics.api_calls"},
                "total_api_calls": {"$sum": "$usage_logs.metrics.api_calls"},
                "avg_storage_mb": {"$avg": "$usage_logs.metrics.storage_mb"}
            }
        },
        {
            "$project": {
                "tier": "$_id",
                "avg_api_calls": {"$round": ["$avg_api_calls", 2]},
                "total_api_calls": 1,
                "avg_storage_mb": {"$round": ["$avg_storage_mb", 2]}
            }
        },
        {"$sort": {"avg_api_calls": -1}}
    ]

    results = list(users_col.aggregate(pipeline))
    return jsonify(serialize_doc(results)), 200


# find users with unusually high api usage
@analytics_bp.route("/analytics/high-usage", methods=["GET"])
@admin_required
def high_usage_anomalies():
    threshold = int(request.args.get("threshold", 50000))

    pipeline = [
        {"$unwind": "$usage_logs"},
        {"$match": {"usage_logs.metrics.api_calls": {"$gt": threshold}}},
        {
            "$project": {
                "_id": 1,
                "email": "$profile.email",
                "subscription_tier": "$subscription.tier",
                "api_calls": "$usage_logs.metrics.api_calls",
                "endpoint": "$usage_logs.request.endpoint",
                "region": "$usage_logs.request.region",
                "timestamp": "$usage_logs.timestamp"
            }
        },
        {"$sort": {"api_calls": -1}}
    ]

    results = list(users_col.aggregate(pipeline))
    return jsonify({"threshold": threshold, "count": len(results), "results": serialize_doc(results)}), 200


# users with failed logins above a threshold
@analytics_bp.route("/analytics/failed-logins", methods=["GET"])
@admin_required
def detect_failed_logins():
    threshold = int(request.args.get("threshold", 3))

    pipeline = [
        {"$match": {"action_type": "failed_login"}},
        {
            "$group": {
                "_id": "$user_id",
                "user_email": {"$first": "$user_email"},
                "count": {"$sum": 1},
                "last_attempt": {"$max": "$timestamp"}
            }
        },
        {"$match": {"count": {"$gte": threshold}}},
        {"$sort": {"count": -1}}
    ]

    results = list(activity_logs_col.aggregate(pipeline))
    return jsonify({"threshold": threshold, "flagged_users": len(results), "results": serialize_doc(results)}), 200


# count of anomalies grouped by severity
@analytics_bp.route("/analytics/anomaly-summary", methods=["GET"])
@admin_required
def anomaly_summary():
    pipeline = [
        {
            "$group": {
                "_id": "$severity",
                "total": {"$sum": 1},
                "resolved": {"$sum": {"$cond": ["$resolved", 1, 0]}},
                "avg_score": {"$avg": "$anomaly_score"}
            }
        },
        {
            "$project": {
                "severity": "$_id",
                "total": 1,
                "resolved": 1,
                "unresolved": {"$subtract": ["$total", "$resolved"]},
                "avg_score": {"$round": ["$avg_score", 2]}
            }
        },
        {"$sort": {"total": -1}}
    ]

    results = list(anomaly_flags_col.aggregate(pipeline))
    return jsonify(serialize_doc(results)), 200


# search activity logs by action type and region
@analytics_bp.route("/analytics/search-logs", methods=["GET"])
@admin_required
def search_activity_logs():
    query = {}

    if request.args.get("action_types"):
        types = request.args.get("action_types").split(",")
        query["action_type"] = {"$in": types}

    if request.args.get("regions"):
        regions = request.args.get("regions").split(",")
        query["network.region"] = {"$in": regions}

    if request.args.get("status_code"):
        query["performance.status_code"] = int(request.args.get("status_code"))

    page_num = int(request.args.get("pn", 1))
    page_size = int(request.args.get("ps", 10))
    skip = (page_num - 1) * page_size

    total = activity_logs_col.count_documents(query)
    logs = list(activity_logs_col.find(query).sort("timestamp", -1).skip(skip).limit(page_size))

    return jsonify({"total": total, "page": page_num, "per_page": page_size, "logs": serialize_doc(logs)}), 200


# geo query - find businesses/logs near a location using $geoNear pipeline
# based on the approach from BE07 practical material
@analytics_bp.route("/analytics/nearby-activity", methods=["GET"])
@admin_required
def nearby_activity():
    lng = float(request.args.get("lng", -0.1278))
    lat = float(request.args.get("lat", 51.5074))
    max_distance = int(request.args.get("max_distance", 5000000))

    # create the 2dsphere index if it doesn't exist
    activity_logs_col.create_index([("network.location", "2dsphere")])

    pipeline = [
        {
            "$geoNear": {
                "near": {"type": "Point", "coordinates": [lng, lat]},
                "distanceField": "distance_metres",
                "maxDistance": max_distance,
                "spherical": True
            }
        },
        {
            "$project": {
                "user_email": 1,
                "action_type": 1,
                "network.region": 1,
                "network.location": 1,
                "timestamp": 1,
                "distance_metres": 1
            }
        },
        {"$limit": 20}
    ]

    results = list(activity_logs_col.aggregate(pipeline))
    return jsonify({"count": len(results), "results": serialize_doc(results)}), 200