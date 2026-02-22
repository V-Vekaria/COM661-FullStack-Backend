from flask import Blueprint, request, jsonify
from config import db
from bson import ObjectId
from datetime import datetime

user_bp = Blueprint("users", __name__)
users_collection = db["users"]


# --------------------------------------------------
# Helper: Build Safe ID Query (Supports String + ObjectId)
# --------------------------------------------------
def build_id_query(id):
    if ObjectId.is_valid(id):
        return {"_id": ObjectId(id)}
    return {"_id": id}


# --------------------------------------------------
# CREATE USER
# --------------------------------------------------
@user_bp.route("/users", methods=["POST"])
def create_user():

    data = request.json

    if not data or "email" not in data:
        return jsonify({"error": "Email is required"}), 400

    user = {
        "email": data.get("email"),
        "role": data.get("role", "user"),
        "subscription_tier": data.get("subscription_tier", "free"),
        "account_status": "active",
        "usage_logs": []
    }

    result = users_collection.insert_one(user)

    return jsonify({
        "message": "User created",
        "user_id": str(result.inserted_id)
    }), 201


# --------------------------------------------------
# GET ALL USERS (Pagination)
# --------------------------------------------------
@user_bp.route("/users", methods=["GET"])
def get_users():

    page_num = int(request.args.get("pn", 1))
    page_size = int(request.args.get("ps", 5))
    page_start = (page_num - 1) * page_size

    users_list = []

    for user in users_collection.find().skip(page_start).limit(page_size):

        # Convert ObjectId if needed
        if isinstance(user["_id"], ObjectId):
            user["_id"] = str(user["_id"])

        for log in user.get("usage_logs", []):
            if isinstance(log["_id"], ObjectId):
                log["_id"] = str(log["_id"])

        users_list.append(user)

    return jsonify(users_list), 200


# --------------------------------------------------
# GET ONE USER
# --------------------------------------------------
@user_bp.route("/users/<string:id>", methods=["GET"])
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


# --------------------------------------------------
# UPDATE USER
# --------------------------------------------------
@user_bp.route("/users/<string:id>", methods=["PUT"])
def update_user(id):

    data = request.json

    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    update_fields = {}

    for field in ["email", "subscription_tier", "account_status"]:
        if field in data:
            update_fields[field] = data[field]

    if not update_fields:
        return jsonify({"error": "No valid fields provided"}), 400

    query = build_id_query(id)

    result = users_collection.update_one(
        query,
        {"$set": update_fields}
    )

    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User updated successfully"}), 200


# --------------------------------------------------
# DELETE USER
# --------------------------------------------------
@user_bp.route("/users/<string:id>", methods=["DELETE"])
def delete_user(id):

    query = build_id_query(id)

    result = users_collection.delete_one(query)

    if result.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User deleted"}), 200


# --------------------------------------------------
# ADD USAGE LOG
# --------------------------------------------------
@user_bp.route("/users/<string:id>/usage", methods=["POST"])
def add_usage_log(id):

    data = request.json

    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    if "api_calls" not in data or "storage_mb" not in data:
        return jsonify({"error": "api_calls and storage_mb are required"}), 400

    usage_log = {
        "_id": ObjectId(),
        "api_calls": data["api_calls"],
        "storage_mb": data["storage_mb"],
        "timestamp": datetime.utcnow().isoformat()
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


# --------------------------------------------------
# GET USAGE LOGS
# --------------------------------------------------
@user_bp.route("/users/<string:id>/usage", methods=["GET"])
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


# --------------------------------------------------
# DELETE USAGE LOG
# --------------------------------------------------
@user_bp.route("/users/<string:user_id>/usage/<string:log_id>", methods=["DELETE"])
def delete_usage_log(user_id, log_id):

    user_query = build_id_query(user_id)

    log_query = log_id
    if ObjectId.is_valid(log_id):
        log_query = ObjectId(log_id)

    result = users_collection.update_one(
        user_query,
        {"$pull": {"usage_logs": {"_id": log_query}}}
    )

    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "Usage log deleted"}), 200


# --------------------------------------------------
# ANALYTICS: Average API Calls Per User
# --------------------------------------------------
@user_bp.route("/analytics/avg-api-calls", methods=["GET"])
def avg_api_calls_per_user():

    pipeline = [
        {"$unwind": "$usage_logs"},
        {
            "$group": {
                "_id": "$_id",
                "email": {"$first": "$email"},
                "subscription_tier": {"$first": "$subscription_tier"},
                "average_api_calls": {"$avg": "$usage_logs.api_calls"}
            }
        },
        {"$sort": {"average_api_calls": -1}}
    ]

    results = list(users_collection.aggregate(pipeline))

    for r in results:
        if isinstance(r["_id"], ObjectId):
            r["_id"] = str(r["_id"])

    return jsonify(results), 200


# --------------------------------------------------
# ANALYTICS: High Usage Anomalies
# --------------------------------------------------
@user_bp.route("/analytics/high-usage-anomalies", methods=["GET"])
def detect_high_usage_anomalies():

    pipeline = [
        {"$unwind": "$usage_logs"},
        {"$match": {"usage_logs.api_calls": {"$gt": 50000}}},
        {
            "$project": {
                "_id": 1,
                "email": 1,
                "subscription_tier": 1,
                "api_calls": "$usage_logs.api_calls",
                "timestamp": "$usage_logs.timestamp"
            }
        }
    ]

    results = list(users_collection.aggregate(pipeline))

    for r in results:
        if isinstance(r["_id"], ObjectId):
            r["_id"] = str(r["_id"])

    return jsonify(results), 200