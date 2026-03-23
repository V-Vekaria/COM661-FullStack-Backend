from flask import Blueprint, request, jsonify
from config import db
from bson import ObjectId
from datetime import datetime
from auth import basic_auth_required, admin_required
import bcrypt

user_bp = Blueprint("users", __name__)
users_collection = db["users"]
login_collection = db["login"]


# =========================
# HELPER FUNCTION
# =========================
def build_id_query(id):
    if not ObjectId.is_valid(id):
        return None
    return {"_id": ObjectId(id)}


def format_user(user):
    return {
        "id": str(user["_id"]),
        "name": user.get("profile", {}).get("name"),
        "email": user.get("profile", {}).get("email"),
        "role": user.get("profile", {}).get("role"),
        "subscription": user.get("subscription", {}).get("tier"),
        "status": user.get("subscription", {}).get("status")
    }


# =========================
# CREATE USER
# =========================
@user_bp.route("/users", methods=["POST"])
@admin_required
def create_user():

    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password")
    role = request.form.get("role", "user")
    subscription_tier = request.form.get("subscription_tier", "free")

    if not name or not email or not password:
        return jsonify({"error": "Name, email, password required"}), 400

    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    user = {
        "profile": {
            "name": name,
            "email": email,
            "role": role,
            "created_at": datetime.utcnow().isoformat()
        },
        "subscription": {
            "tier": subscription_tier,
            "status": "active"
        },
        "usage_logs": [],
        "api_keys": [],
        "alerts": []
    }

    result = users_collection.insert_one(user)

    login_doc = {
        "name": name,
        "email": email,
        "password": hashed_password,
        "role": role,
        "user_id": str(result.inserted_id)
    }

    login_collection.insert_one(login_doc)

    return jsonify({
        "message": "User created",
        "user_id": str(result.inserted_id)
    }), 201


# =========================
# GET USERS (WITH SEARCH + PAGINATION)
# =========================
@user_bp.route("/users", methods=["GET"])
@admin_required
def get_users():

    name = request.args.get("name")
    page_num = int(request.args.get("pn", 1))
    page_size = int(request.args.get("ps", 5))
    skip = (page_num - 1) * page_size

    query = {}

    if name:
        query["profile.name"] = {"$regex": name, "$options": "i"}

    users = users_collection.find(query).skip(skip).limit(page_size)

    results = [format_user(user) for user in users]

    return jsonify({"data": results}), 200


# =========================
# GET ONE USER
# =========================
@user_bp.route("/users/<string:id>", methods=["GET"])
@basic_auth_required
def get_one_user(id):

    query = build_id_query(id)
    if query is None:
        return jsonify({"error": "Invalid ID format"}), 400

    user = users_collection.find_one(query)

    if user is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify(format_user(user)), 200


# =========================
# UPDATE USER
# =========================
@user_bp.route("/users/<string:id>", methods=["PUT"])
@basic_auth_required
def update_user(id):

    query = build_id_query(id)
    if query is None:
        return jsonify({"error": "Invalid ID format"}), 400

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

    result = users_collection.update_one(query, {"$set": update_fields})

    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User updated"}), 200


# =========================
# DELETE USER
# =========================
@user_bp.route("/users/<string:id>", methods=["DELETE"])
@admin_required
def delete_user(id):

    query = build_id_query(id)
    if query is None:
        return jsonify({"error": "Invalid ID format"}), 400

    result = users_collection.delete_one(query)

    if result.deleted_count == 0:
        return jsonify({"error": "User not found"}), 404

    # ALSO delete login
    login_collection.delete_one({"user_id": id})

    return jsonify({"message": "User deleted"}), 200


# =========================
# ADD USAGE LOG
# =========================
@user_bp.route("/users/<string:id>/usage", methods=["POST"])
@admin_required
def add_usage_log(id):

    query = build_id_query(id)
    if query is None:
        return jsonify({"error": "Invalid ID format"}), 400

    api_calls = request.form.get("api_calls")
    storage_mb = request.form.get("storage_mb")

    if not api_calls or not storage_mb:
        return jsonify({"error": "api_calls and storage_mb required"}), 400

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


# =========================
# GET USAGE LOGS
# =========================
@user_bp.route("/users/<string:id>/usage", methods=["GET"])
@basic_auth_required
def get_usage_logs(id):

    query = build_id_query(id)
    if query is None:
        return jsonify({"error": "Invalid ID format"}), 400

    user = users_collection.find_one(query)

    if user is None:
        return jsonify({"error": "User not found"}), 404

    logs = [
        {**log, "_id": str(log["_id"])}
        for log in user.get("usage_logs", [])
    ]

    return jsonify(logs), 200


# =========================
# ANALYTICS
# =========================
@user_bp.route("/analytics/avg-api-calls", methods=["GET"])
@admin_required
def avg_api_calls():

    pipeline = [
        {"$unwind": "$usage_logs"},
        {
            "$group": {
                "_id": "$_id",
                "email": {"$first": "$profile.email"},
                "avg_api_calls": {"$avg": "$usage_logs.metrics.api_calls"}
            }
        },
        {"$sort": {"avg_api_calls": -1}}
    ]

    results = list(users_collection.aggregate(pipeline))

    for r in results:
        r["_id"] = str(r["_id"])

    return jsonify(results), 200


@user_bp.route("/analytics/high-usage-anomalies", methods=["GET"])
@admin_required
def high_usage():

    pipeline = [
        {"$unwind": "$usage_logs"},
        {"$match": {"usage_logs.metrics.api_calls": {"$gt": 50000}}},
        {
            "$project": {
                "_id": 1,
                "email": "$profile.email",
                "api_calls": "$usage_logs.metrics.api_calls"
            }
        }
    ]

    results = list(users_collection.aggregate(pipeline))

    for r in results:
        r["_id"] = str(r["_id"])

    return jsonify(results), 200