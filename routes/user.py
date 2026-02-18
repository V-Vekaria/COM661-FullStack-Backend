from flask import Blueprint, request, jsonify
from pymongo import MongoClient
from bson import ObjectId

user_bp = Blueprint("users", __name__)

client = MongoClient("mongodb://localhost:27017/")
db = client["saas_monitoring"]
users_collection = db["users"]


@user_bp.route("/users", methods=["POST"])
def create_user():
    data = request.json

    user = {
        "email": data.get("email"),
        "role": data.get("role", "user"),
        "subscription_tier": data.get("subscription_tier", "free"),
        "account_status": "active"
    }

    result = users_collection.insert_one(user)

    return jsonify({
        "message": "User created",
        "user_id": str(result.inserted_id)
    }), 201


@user_bp.route("/users", methods=["GET"])
def get_users():
    users = []

    for user in users_collection.find():
        user["_id"] = str(user["_id"])
        users.append(user)

    return jsonify(users), 200
