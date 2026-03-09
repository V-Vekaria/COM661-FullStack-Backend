import json
import random
import bcrypt
from datetime import datetime, timedelta
from bson import ObjectId

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

    for _ in range(random.randint(3, 5)):
        log = {
            "_id": str(ObjectId()),
            "timestamp": random_date(),
            "metrics": {
                "api_calls": random.randint(100, 5000),
                "storage_mb": random.randint(100, 5000)
            },
            "request": {
                "endpoint": random.choice(endpoints),
                "region": random.choice(regions)
            }
        }
        logs.append(log)
    return logs


login_users = []
users = []
admin_exists = False


for i in range(NUM_USERS):

    name = names[i]
    email = f"{name}@{DOMAIN}"

    role = random.choice(["admin", "user"])

    if role == "admin":
        admin_exists = True

    password = "password123"
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    user_id = str(ObjectId())

    login_user = {
        "email": email,
        "password": hashed_password.decode("utf-8"),
        "role": role,
        "user_id": user_id
    }

    user = {
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

    login_users.append(login_user)
    users.append(user)


if not admin_exists:
    login_users[0]["role"] = "admin"
    users[0]["profile"]["role"] = "admin"


with open("login_users.json", "w") as f:
    json.dump(login_users, f, indent=4)

with open("users.json", "w") as f:
    json.dump(users, f, indent=4)


print("Synthetic datasets generated successfully.")