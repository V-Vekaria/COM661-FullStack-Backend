from flask import Blueprint, request, jsonify
from config import db
from bson import ObjectId
from datetime import datetime
from auth import jwt_required, admin_required
import bcrypt

user_bp = Blueprint("users", __name__)
users_collection = db["users"]


# HELPER FUNCTION
def build_id_query(id):
    if ObjectId.is_valid(id):
        return {"_id": ObjectId(id)}
    return {"_id": id}


# CREATE USER
@user_bp.route("/users", methods=["POST"])
@admin_required
def create_user():

    email = request.form.get("email")
    password = request.form.get("password")
    role = request.form.get("role", "user")
    subscription_tier = request.form.get("subscription_tier", "free")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    if not password:
        return jsonify({"error": "Password is required"}), 400

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    user = {
        "profile": {
            "email": email,
            "role": role,
            "created_at": datetime.utcnow().isoformat()
        },
        "password": hashed_password,
        "subscription": {
            "tier": subscription_tier,
            "status": "active"
        },
        "usage_logs": [],
        "api_keys": [],
        "alerts": []
    }

    result = users_collection.insert_one(user)

    return jsonify({
        "message": "User created",
        "user_id": str(result.inserted_id)
    }), 201


# GET ALL USERS
@user_bp.route("/users", methods=["GET"])
@admin_required
def get_users():

    page_num = int(request.args.get("pn", 1))
    page_size = int(request.args.get("ps", 5))
    page_start = (page_num - 1) * page_size

    users_list = []

    for user in users_collection.find().skip(page_start).limit(page_size):

        if isinstance(user["_id"], ObjectId):
            user["_id"] = str(user["_id"])

        for log in user.get("usage_logs", []):
            if isinstance(log["_id"], ObjectId):
                log["_id"] = str(log["_id"])

        users_list.append(user)

    return jsonify(users_list), 200


# GET ONE USER
@user_bp.route("/users/<string:id>", methods=["GET"])
@jwt_required
def get_one_user(id):

    query = build_id_query(id)
    user = users_collection.find_one(query)

    if user is None:
        return jsonify({"error": "User not found"}), 404

    if isinstance(user["_id"], ObjectId):
        user["_id"] = str(user["_id"])

    for log in user.get("usage_logs", []):
        if isinstance(log["_id"], ObjectId):
            log["_id"] = str(log["_id"])

    return jsonify(user), 200


# UPDATE USER
@user_bp.route("/users/<string:id>", methods=["PUT"])
@jwt_required
def update_user(id):

    email = request.form.get("email")
    subscription_tier = request.form.get("subscription_tier")
    account_status = request.form.get("account_status")

    update_fields = {}

    if email:
        update_fields["profile.email"] = email

    if subscription_tier:
        update_fields["subscription.tier"] = subscription_tier

    if account_status:
        update_fields["subscription.status"] = account_status

    if not update_fields:
        return jsonify({"error": "No fields to update"}), 400

    query = build_id_query(id)

    result = users_collection.update_one(query, {"$set": update_fields})

    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User updated successfully"}), 200


# DELETE USER
@user_bp.route("/users/<string:id>", methods=["DELETE"])
@admin_required
def delete_user(id):

    query = build_id_query(id)

    result = users_collection.delete_one(query)

    if result.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User deleted"}), 200


# ADD USAGE LOG
@user_bp.route("/users/<string:id>/usage", methods=["POST"])
@admin_required
def add_usage_log(id):

    api_calls = request.form.get("api_calls")
    storage_mb = request.form.get("storage_mb")

    if not api_calls or not storage_mb:
        return jsonify({"error": "api_calls and storage_mb are required"}), 400

    usage_log = {
        "_id": ObjectId(),
        "timestamp": datetime.utcnow().isoformat(),
        "metrics": {
            "api_calls": int(api_calls),
            "storage_mb": int(storage_mb)
        },
        "request": {
            "endpoint": "/api/upload",
            "method": "POST",
            "status_code": 200,
            "region": "eu-west"
        }
    }

    query = build_id_query(id)

    result = users_collection.update_one(
        query,
        {"$push": {"usage_logs": usage_log}}
    )

    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    usage_log["_id"] = str(usage_log["_id"])

    return jsonify({
        "message": "Usage log added",
        "usage_log": usage_log
    }), 201


# GET USAGE LOGS
@user_bp.route("/users/<string:id>/usage", methods=["GET"])
@jwt_required
def get_usage_logs(id):

    query = build_id_query(id)

    user = users_collection.find_one(query)

    if user is None:
        return jsonify({"error": "User not found"}), 404

    logs = user.get("usage_logs", [])

    for log in logs:
        if isinstance(log["_id"], ObjectId):
            log["_id"] = str(log["_id"])

    return jsonify(logs), 200


# DELETE USAGE LOG
@user_bp.route("/users/<string:user_id>/usage/<string:log_id>", methods=["DELETE"])
@admin_required
def delete_usage_log(user_id, log_id):

    user_query = build_id_query(user_id)

    log_query = ObjectId(log_id) if ObjectId.is_valid(log_id) else log_id

    result = users_collection.update_one(
        user_query,
        {"$pull": {"usage_logs": {"_id": log_query}}}
    )

    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "Usage log deleted"}), 200


# ANALYTICS: AVERAGE API CALLS
@user_bp.route("/analytics/avg-api-calls", methods=["GET"])
@admin_required
def avg_api_calls_per_user():

    pipeline = [

        {"$unwind": "$usage_logs"},

        {
            "$group": {
                "_id": "$_id",
                "email": {"$first": "$profile.email"},
                "subscription_tier": {"$first": "$subscription.tier"},
                "average_api_calls": {"$avg": "$usage_logs.metrics.api_calls"}
            }
        },

        {"$sort": {"average_api_calls": -1}}
    ]

    results = list(users_collection.aggregate(pipeline))

    for r in results:
        if isinstance(r["_id"], ObjectId):
            r["_id"] = str(r["_id"])

    return jsonify(results), 200


# ANALYTICS: HIGH USAGE ANOMALIES
@user_bp.route("/analytics/high-usage-anomalies", methods=["GET"])
@admin_required
def detect_high_usage_anomalies():

    pipeline = [

        {"$unwind": "$usage_logs"},

        {"$match": {"usage_logs.metrics.api_calls": {"$gt": 50000}}},

        {
            "$project": {
                "_id": 1,
                "email": "$profile.email",
                "subscription_tier": "$subscription.tier",
                "api_calls": "$usage_logs.metrics.api_calls",
                "timestamp": "$usage_logs.timestamp"
            }
        }
    ]

    results = list(users_collection.aggregate(pipeline))

    for r in results:
        if isinstance(r["_id"], ObjectId):
            r["_id"] = str(r["_id"])

    return jsonify(results), 200