from flask import Blueprint, request, jsonify
from config import db

# --------------------------------------------------
# Users Blueprint
# Handles full CRUD operations for SaaS users
# Uses string-based _id values (not MongoDB ObjectId)
# --------------------------------------------------

user_bp = Blueprint("users", __name__)
users_collection = db["users"]


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
# GET ALL USERS (Pagination Supported)
# --------------------------------------------------
@user_bp.route("/users", methods=["GET"])
def get_users():

    page_num = int(request.args.get("pn", 1))
    page_size = int(request.args.get("ps", 5))

    page_start = (page_num - 1) * page_size

    users_list = []

    for user in users_collection.find().skip(page_start).limit(page_size):
        users_list.append(user)

    return jsonify(users_list), 200


# --------------------------------------------------
# GET ONE USER BY ID (String-based ID)
# --------------------------------------------------
@user_bp.route("/users/<string:id>", methods=["GET"])
def get_one_user(id):

    user = users_collection.find_one({"_id": id})

    if user is None:
        return jsonify({"error": "User not found"}), 404

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

    # Only allow controlled fields to be updated
    for field in ["email", "subscription_tier", "account_status"]:
        if field in data:
            update_fields[field] = data[field]

    if not update_fields:
        return jsonify({"error": "No valid fields provided"}), 400

    result = users_collection.update_one(
        {"_id": id},
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

    result = users_collection.delete_one({"_id": id})

    if result.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User deleted"}), 200

# --------------------------------------------------
# ADD USAGE LOG TO USER (Sub-document)
# --------------------------------------------------
@user_bp.route("/users/<string:id>/usage", methods=["POST"])
def add_usage_log(id):

    data = request.json

    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    if "api_calls" not in data or "storage_mb" not in data:
        return jsonify({"error": "api_calls and storage_mb are required"}), 400

    # Create usage log entry
    usage_log = {
        "_id": str(__import__("bson").ObjectId()),
        "api_calls": data["api_calls"],
        "storage_mb": data["storage_mb"],
        "timestamp": __import__("datetime").datetime.utcnow().isoformat()
    }

    result = users_collection.update_one(
        {"_id": id},
        {"$push": {"usage_logs": usage_log}}
    )

    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "message": "Usage log added",
        "usage_log": usage_log
    }), 201

# --------------------------------------------------
# GET ALL USAGE LOGS FOR A USER
# --------------------------------------------------
@user_bp.route("/users/<string:id>/usage", methods=["GET"])
def get_usage_logs(id):

    user = users_collection.find_one({"_id": id})

    if user is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify(user.get("usage_logs", [])), 200

# --------------------------------------------------
# DELETE SPECIFIC USAGE LOG
# --------------------------------------------------
@user_bp.route("/users/<string:user_id>/usage/<string:log_id>", methods=["DELETE"])
def delete_usage_log(user_id, log_id):

    result = users_collection.update_one(
        {"_id": user_id},
        {"$pull": {"usage_logs": {"_id": log_id}}}
    )

    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "Usage log deleted"}), 200

