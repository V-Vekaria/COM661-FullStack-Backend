from pymongo import MongoClient
import random
import bcrypt
from datetime import datetime, timedelta
from bson import ObjectId

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["saas_monitoring"]

users_collection = db["users"]
login_collection = db["login"]

# reset collections
users_collection.delete_many({})
login_collection.delete_many({})

NUM_USERS = random.randint(10, 15)

regions = ["eu-west", "us-east", "ap-south"]
endpoints = ["/api/upload", "/api/download", "/api/analytics"]
subscription_tiers = ["free", "pro", "enterprise"]

names = [
    "alice","bob","charlie","diana","ethan","fiona","george",
    "hannah","ivan","julia","kevin","laura","michael","nina","oliver"
]

DOMAIN = "cloudmetrics.io"


def random_date(days=60):
    return (datetime.utcnow() - timedelta(days=random.randint(1, days))).isoformat()


def generate_usage_logs():

    logs = []

    for _ in range(random.randint(3,5)):

        log = {
            "_id": ObjectId(),
            "timestamp": random_date(),
            "metrics": {
                "api_calls": random.randint(100, 80000),
                "storage_mb": random.randint(100, 5000)
            },
            "request": {
                "endpoint": random.choice(endpoints),
                "region": random.choice(regions),
                "method": random.choice(["GET","POST"])
            }
        }

        logs.append(log)

    return logs


admin_exists = False

for i in range(NUM_USERS):

    name = names[i]
    email = f"{name}@{DOMAIN}"

    role = random.choice(["admin","user"])

    if role == "admin":
        admin_exists = True

    password = "password123"
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    user_id = ObjectId()

    # USERS COLLECTION DOCUMENT
    user_doc = {
        "_id": user_id,
        "profile": {
            "email": email,
            "role": role,
            "created_at": random_date(120)
        },
        "subscription": {
            "tier": random.choice(subscription_tiers),
            "status": "active"
        },
        "usage_logs": generate_usage_logs(),
        "api_keys": [],
        "alerts": []
    }

    users_collection.insert_one(user_doc)

    # LOGIN COLLECTION DOCUMENT
    login_doc = {
        "email": email,
        "password": hashed_password.decode("utf-8"),
        "role": role,
        "user_id": str(user_id)
    }

    login_collection.insert_one(login_doc)


# ensure at least one admin exists
if not admin_exists:

    first_user = users_collection.find_one()

    users_collection.update_one(
        {"_id": first_user["_id"]},
        {"$set": {"profile.role": "admin"}}
    )

    login_collection.update_one(
        {"user_id": str(first_user["_id"])},
        {"$set": {"role": "admin"}}
    )

print("Database seeded successfully with clean ObjectId data.")