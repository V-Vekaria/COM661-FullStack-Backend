from flask import Blueprint, jsonify, request
from bson import ObjectId
from config import db
from auth import analyst_or_admin

analytics_bp = Blueprint("analytics", __name__)

users_col         = db["users"]
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


def err(msg, field=None, code=400):
    body = {"error": msg}
    if field:
        body["field"] = field
    return jsonify(body), code


# ---------------------------------------------------------------------------
# DASHBOARD SUMMARY — single call for frontend overview page
# ---------------------------------------------------------------------------

@analytics_bp.route("/dashboard/summary", methods=["GET"])
@analyst_or_admin
def dashboard_summary():
    total_users    = users_col.count_documents({})
    active_users   = users_col.count_documents({"subscription.status": "active"})
    open_anomalies = anomaly_flags_col.count_documents({"resolved": False})
    critical_count = anomaly_flags_col.count_documents({"severity": "critical", "resolved": False})

    # activity in last 24h using string prefix match (timestamps stored as ISO strings)
    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    activity_24h = activity_logs_col.count_documents({"timestamp": {"$gte": cutoff}})

    # tier breakdown via aggregation
    tier_pipeline = [
        {"$group": {"_id": "$subscription.tier", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    tier_results = list(users_col.aggregate(tier_pipeline))
    tier_breakdown = {r["_id"]: r["count"] for r in tier_results if r["_id"]}

    # churn risk breakdown
    churn_pipeline = [
        {"$group": {"_id": "$metadata.churn_risk", "count": {"$sum": 1}}},
    ]
    churn_results = list(users_col.aggregate(churn_pipeline))
    churn_breakdown = {r["_id"]: r["count"] for r in churn_results if r["_id"]}

    return jsonify({
        "total_users":       total_users,
        "active_users":      active_users,
        "open_anomalies":    open_anomalies,
        "critical_anomalies": critical_count,
        "activity_last_24h": activity_24h,
        "tier_breakdown":    tier_breakdown,
        "churn_risk_breakdown": churn_breakdown,
    }), 200


# ---------------------------------------------------------------------------
# AVERAGE API CALLS PER USER
# ---------------------------------------------------------------------------

@analytics_bp.route("/analytics/avg-api-calls", methods=["GET"])
@analyst_or_admin
def avg_api_calls_per_user():
    pipeline = [
        {"$unwind": "$usage_logs"},
        {
            "$group": {
                "_id":             "$_id",
                "email":           {"$first": "$profile.email"},
                "subscription_tier": {"$first": "$subscription.tier"},
                "avg_api_calls":   {"$avg": "$usage_logs.metrics.api_calls"},
                "total_api_calls": {"$sum": "$usage_logs.metrics.api_calls"},
            }
        },
        {
            "$project": {
                "email":             1,
                "subscription_tier": 1,
                "avg_api_calls":     {"$round": ["$avg_api_calls", 2]},
                "total_api_calls":   1,
            }
        },
        {"$sort": {"avg_api_calls": -1}},
    ]
    results = list(users_col.aggregate(pipeline))
    return jsonify(serialize_doc(results)), 200


# ---------------------------------------------------------------------------
# AVERAGE API CALLS BY SUBSCRIPTION TIER
# ---------------------------------------------------------------------------

@analytics_bp.route("/analytics/avg-api-calls-by-tier", methods=["GET"])
@analyst_or_admin
def avg_api_calls_by_tier():
    pipeline = [
        {"$unwind": "$usage_logs"},
        {
            "$group": {
                "_id":             "$subscription.tier",
                "avg_api_calls":   {"$avg": "$usage_logs.metrics.api_calls"},
                "total_api_calls": {"$sum": "$usage_logs.metrics.api_calls"},
                "avg_storage_mb":  {"$avg": "$usage_logs.metrics.storage_mb"},
            }
        },
        {
            "$project": {
                "tier":            "$_id",
                "avg_api_calls":   {"$round": ["$avg_api_calls", 2]},
                "total_api_calls": 1,
                "avg_storage_mb":  {"$round": ["$avg_storage_mb", 2]},
            }
        },
        {"$sort": {"avg_api_calls": -1}},
    ]
    results = list(users_col.aggregate(pipeline))
    return jsonify(serialize_doc(results)), 200


# ---------------------------------------------------------------------------
# HIGH USAGE ANOMALY DETECTION
# ---------------------------------------------------------------------------

@analytics_bp.route("/analytics/high-usage", methods=["GET"])
@analyst_or_admin
def high_usage_anomalies():
    try:
        threshold = int(request.args.get("threshold", 50000))
    except ValueError:
        return err("threshold must be an integer", "threshold", 422)
    if threshold <= 0:
        return err("threshold must be greater than 0", "threshold", 422)

    pipeline = [
        {"$unwind": "$usage_logs"},
        {"$match": {"usage_logs.metrics.api_calls": {"$gt": threshold}}},
        {
            "$project": {
                "_id":              1,
                "email":            "$profile.email",
                "subscription_tier": "$subscription.tier",
                "api_calls":        "$usage_logs.metrics.api_calls",
                "endpoint":         "$usage_logs.request.endpoint",
                "region":           "$usage_logs.request.region",
                "timestamp":        "$usage_logs.timestamp",
            }
        },
        {"$sort": {"api_calls": -1}},
    ]
    results = list(users_col.aggregate(pipeline))
    return jsonify({"threshold": threshold, "count": len(results), "results": serialize_doc(results)}), 200


# ---------------------------------------------------------------------------
# FAILED LOGIN DETECTION — aggregation on activity_logs collection
# ---------------------------------------------------------------------------

@analytics_bp.route("/analytics/failed-logins", methods=["GET"])
@analyst_or_admin
def detect_failed_logins():
    try:
        threshold = int(request.args.get("threshold", 3))
    except ValueError:
        return err("threshold must be an integer", "threshold", 422)
    if threshold <= 0:
        return err("threshold must be greater than 0", "threshold", 422)

    pipeline = [
        {"$match": {"action_type": "failed_login"}},
        {
            "$group": {
                "_id":          "$user_id",
                "user_email":   {"$first": "$user_email"},
                "count":        {"$sum": 1},
                "last_attempt": {"$max": "$timestamp"},
            }
        },
        {"$match": {"count": {"$gte": threshold}}},
        {"$sort": {"count": -1}},
    ]
    results = list(activity_logs_col.aggregate(pipeline))
    return jsonify({"threshold": threshold, "flagged_users": len(results), "results": serialize_doc(results)}), 200


# ---------------------------------------------------------------------------
# ANOMALY SUMMARY BY SEVERITY
# ---------------------------------------------------------------------------

@analytics_bp.route("/analytics/anomaly-summary", methods=["GET"])
@analyst_or_admin
def anomaly_summary():
    pipeline = [
        {
            "$group": {
                "_id":       "$severity",
                "total":     {"$sum": 1},
                "resolved":  {"$sum": {"$cond": ["$resolved", 1, 0]}},
                "avg_score": {"$avg": "$anomaly_score"},
            }
        },
        {
            "$project": {
                "severity":   "$_id",
                "total":      1,
                "resolved":   1,
                "unresolved": {"$subtract": ["$total", "$resolved"]},
                "avg_score":  {"$round": ["$avg_score", 2]},
            }
        },
        {"$sort": {"total": -1}},
    ]
    results = list(anomaly_flags_col.aggregate(pipeline))
    return jsonify(serialize_doc(results)), 200


# ---------------------------------------------------------------------------
# SEARCH ACTIVITY LOGS — multi-param filter + pagination
# ---------------------------------------------------------------------------

@analytics_bp.route("/analytics/search-logs", methods=["GET"])
@analyst_or_admin
def search_activity_logs():
    query = {}

    if request.args.get("action_types"):
        types = [t.strip() for t in request.args.get("action_types").split(",")]
        query["action_type"] = {"$in": types}
    if request.args.get("regions"):
        regions = [r.strip() for r in request.args.get("regions").split(",")]
        query["network.region"] = {"$in": regions}
    if request.args.get("status_code"):
        try:
            query["performance.status_code"] = int(request.args.get("status_code"))
        except ValueError:
            return err("status_code must be an integer", "status_code", 422)

    try:
        page_num  = max(1, int(request.args.get("pn", 1)))
        page_size = min(100, max(1, int(request.args.get("ps", 10))))
    except ValueError:
        page_num, page_size = 1, 10

    skip  = (page_num - 1) * page_size
    total = activity_logs_col.count_documents(query)
    logs  = list(activity_logs_col.find(query).sort("timestamp", -1).skip(skip).limit(page_size))

    return jsonify({
        "total":    total,
        "page":     page_num,
        "per_page": page_size,
        "logs":     serialize_doc(logs),
    }), 200


# ---------------------------------------------------------------------------
# GEO QUERY — find activity near a location using $geoNear
# ---------------------------------------------------------------------------

@analytics_bp.route("/analytics/nearby-activity", methods=["GET"])
@analyst_or_admin
def nearby_activity():
    try:
        lng          = float(request.args.get("lng", -0.1278))
        lat          = float(request.args.get("lat", 51.5074))
        max_distance = int(request.args.get("max_distance", 5000000))
    except ValueError:
        return err("lng and lat must be numbers, max_distance must be integer", code=422)

    if not (-180 <= lng <= 180):
        return err("lng must be between -180 and 180", "lng", 422)
    if not (-90 <= lat <= 90):
        return err("lat must be between -90 and 90", "lat", 422)
    if max_distance <= 0:
        return err("max_distance must be greater than 0", "max_distance", 422)

    activity_logs_col.create_index([("network.location", "2dsphere")])

    pipeline = [
        {
            "$geoNear": {
                "near":          {"type": "Point", "coordinates": [lng, lat]},
                "distanceField": "distance_metres",
                "maxDistance":   max_distance,
                "spherical":     True,
            }
        },
        {
            "$project": {
                "user_email":      1,
                "action_type":     1,
                "network.region":  1,
                "network.location": 1,
                "timestamp":       1,
                "distance_metres": 1,
            }
        },
        {"$limit": 20},
    ]

    results = list(activity_logs_col.aggregate(pipeline))
    return jsonify({"count": len(results), "results": serialize_doc(results)}), 200


# ---------------------------------------------------------------------------
# USER RISK REPORT — $lookup cross-collection join (advanced DB technique)
# ---------------------------------------------------------------------------

@analytics_bp.route("/analytics/user-risk-report", methods=["GET"])
@analyst_or_admin
def user_risk_report():
    pipeline = [
        {
            "$lookup": {
                "from":         "anomaly_flags",
                "localField":   "_id",
                "foreignField": "user_id",
                "as":           "anomalies",
            }
        },
        {
            "$project": {
                "email":          "$profile.email",
                "tier":           "$subscription.tier",
                "status":         "$subscription.status",
                "churn_risk":     "$metadata.churn_risk",
                "total_anomalies": {"$size": "$anomalies"},
                "critical_count": {
                    "$size": {
                        "$filter": {
                            "input": "$anomalies",
                            "cond":  {"$eq": ["$$this.severity", "critical"]},
                        }
                    }
                },
                "unresolved_count": {
                    "$size": {
                        "$filter": {
                            "input": "$anomalies",
                            "cond":  {"$eq": ["$$this.resolved", False]},
                        }
                    }
                },
                "avg_anomaly_score": {
                    "$round": [{"$avg": "$anomalies.anomaly_score"}, 3]
                },
            }
        },
        {"$match": {"total_anomalies": {"$gt": 0}}},
        {"$sort": {"critical_count": -1, "unresolved_count": -1}},
    ]

    results = list(users_col.aggregate(pipeline))
    return jsonify(serialize_doc(results)), 200


# ---------------------------------------------------------------------------
# BREAKDOWN OF READ/WRITE/DELETE OPS — uses metrics.breakdown (4th level)
# ---------------------------------------------------------------------------

@analytics_bp.route("/analytics/ops-breakdown", methods=["GET"])
@analyst_or_admin
def ops_breakdown():
    pipeline = [
        {"$unwind": "$usage_logs"},
        {
            "$group": {
                "_id":          "$subscription.tier",
                "total_reads":  {"$sum": "$usage_logs.metrics.breakdown.read_ops"},
                "total_writes": {"$sum": "$usage_logs.metrics.breakdown.write_ops"},
                "total_deletes": {"$sum": "$usage_logs.metrics.breakdown.delete_ops"},
                "avg_cache_hit": {"$avg": "$usage_logs.metrics.breakdown.cache_hit_pct"},
            }
        },
        {
            "$project": {
                "tier":          "$_id",
                "total_reads":   1,
                "total_writes":  1,
                "total_deletes": 1,
                "avg_cache_hit": {"$round": ["$avg_cache_hit", 1]},
            }
        },
        {"$sort": {"total_reads": -1}},
    ]
    results = list(users_col.aggregate(pipeline))
    return jsonify(serialize_doc(results)), 200