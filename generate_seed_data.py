import random
import json
from datetime import datetime, timedelta
from bson import ObjectId

NUM_USERS = 12

regions = ["eu-west", "us-east", "ap-south"]

endpoints = [
    "/api/upload",
    "/api/download",
    "/api/analytics"
]

methods = ["GET", "POST", "PUT"]
status_codes = [200, 201, 400, 401, 500]

roles = ["admin", "user"]
subscription_tiers = ["free", "pro", "enterprise"]


def random_date(days=60):
    return (datetime.utcnow() - timedelta(days=random.randint(1, days))).isoformat()


def generate_usage_logs():
    logs = []
    for _ in range(random.randint(3, 6)):
        api_calls = random.randint(100, 5000)

        log = {
            "_id": str(ObjectId()),
            "timestamp": random_date(),
            "metrics": {
                "api_calls": api_calls,
                "storage_mb": random.randint(100, 5000)
            },

            "request": {
                "endpoint": random.choice(endpoints),
                "method": random.choice(methods),
                "status_code": random.choice(status_codes),
                "region": random.choice(regions)
            }
        }
        logs.append(log)
    return logs


def generate_user(index):
    profile = {
        "email": f"user{index}@example.com",
        "role": random.choice(roles),
        "company": f"Company-{index}",
        "created_at": random_date(120)
    }
    subscription = {
        "tier": random.choice(subscription_tiers),
        "status": random.choice(["active", "inactive"])
    }
    user = {
        "_id": str(ObjectId()),
        "profile": profile,
        "subscription": subscription,
        "usage_logs": generate_usage_logs(),
        "api_keys": [],
        "alerts": []
    }
    return user


def generate_dataset():
    users = []
    for i in range(1, NUM_USERS + 1):
        users.append(generate_user(i))
    return users


if __name__ == "__main__":
    dataset = generate_dataset()
    with open("seed_users.json", "w") as f:
        json.dump(dataset, f, indent=4)

    print("Dataset generated successfully.")