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

roles = ["admin", "user"]
subscription_tiers = ["free", "pro", "enterprise"]

def random_date(days=60):
    return (datetime.utcnow() - timedelta(days=random.randint(1, days))).isoformat()


def generate_usage_logs():
    logs = []
    for _ in range(random.randint(2,3)):
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
                "region": random.choice(regions)
            }
        }
        logs.append(log)
    return logs


def generate_user(index):
    return {
        "_id": str(ObjectId()),
        "email": f"user{index}@example.com",
        "role": random.choice(roles),
        "subscription_tier": random.choice(subscription_tiers),
        "account_status": random.choice(["active", "inactive"]),
        "usage_logs": generate_usage_logs()
    }


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