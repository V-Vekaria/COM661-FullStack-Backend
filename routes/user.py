from flask import Blueprint, request, jsonify
from config import db
from bson import ObjectId

# --------------------------------------------------
# Users Blueprint
# Handles full CRUD operations for SaaS users
# Includes pagination and ObjectId validation
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
        # Convert ObjectId to string for JSON serialization
        user["_id"] = str(user["_id"])

        # Convert nested usage_logs ObjectIds
        for log in user.get("usage_logs", []):
            log["_id"] = str(log["_id"])

        users_list.append(user)

    return jsonify(users_list), 200


# --------------------------------------------------
# GET ONE USER BY ID
# --------------------------------------------------
@user_bp.route("/users/<string:id>", methods=["GET"])
def get_one_user(id):

    # Validate ObjectId format
    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid user ID format"}), 400

    user = users_collection.find_one({"_id": ObjectId(id)})

    if user is None:
        return jsonify({"error": "User not found"}), 404

    user["_id"] = str(user["_id"])

    for log in user.get("usage_logs", []):
        log["_id"] = str(log["_id"])

    return jsonify(user), 200


# --------------------------------------------------
# UPDATE USER
# --------------------------------------------------
@user_bp.route("/users/<string:id>", methods=["PUT"])
def update_user(id):

    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid user ID format"}), 400

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
        {"_id": ObjectId(id)},
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

    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid user ID format"}), 400

    result = users_collection.delete_one({"_id": ObjectId(id)})

    if result.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User deleted"}), 200