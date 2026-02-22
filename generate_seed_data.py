import random
import json
from datetime import datetime, timedelta
from bson import ObjectId

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------
# Number of synthetic users to generate
NUM_USERS = 15

# Each user will have between MIN_LOGS and MAX_LOGS usage entries
MIN_LOGS = 3
MAX_LOGS = 6

# Tier-based usage modelling
# Each subscription tier has realistic API call and storage ranges
subscription_config = {
    "free": {"api_min": 50, "api_max": 500, "storage_min": 100, "storage_max": 1000},
    "pro": {"api_min": 500, "api_max": 5000, "storage_min": 1000, "storage_max": 5000},
    "enterprise": {"api_min": 5000, "api_max": 20000, "storage_min": 5000, "storage_max": 50000}
}

# --------------------------------------------------
# UTILITY FUNCTIONS
# --------------------------------------------------

def generate_timestamp(days_ago):
    """
    Generate ISO timestamp representing activity in the past.
    Simulates historical SaaS usage logs.
    """
    base_time = datetime.utcnow() - timedelta(days=days_ago)
    return base_time.isoformat()

def generate_usage_log(tier, growth_factor=1.0):
    """
    Generate a single usage log.
    Growth factor simulates increasing usage over time.
    """
    config = subscription_config[tier]

    api_calls = int(random.randint(config["api_min"], config["api_max"]) * growth_factor)
    storage = int(random.randint(config["storage_min"], config["storage_max"]) * growth_factor)

    return {
        "_id": str(ObjectId()),
        "api_calls": api_calls,
        "storage_mb": storage,
        "timestamp": generate_timestamp(random.randint(0, 30))
    }

def generate_user(index):
    """
    Generate a single synthetic SaaS user.
    Includes realistic subscription distribution and account status.
    """

    # Weighted distribution of tiers (more free users than enterprise)
    tier = random.choices(
        ["free", "pro", "enterprise"],
        weights=[0.5, 0.35, 0.15]
    )[0]

    # Small percentage of admin users
    role = "admin" if random.random() < 0.1 else "user"

    # Simulate account lifecycle states
    status = random.choices(
        ["active", "inactive", "suspended"],
        weights=[0.8, 0.1, 0.1]
    )[0]

    usage_logs = []

    # Simulate gradual usage growth over time
    growth = 1.0
    for _ in range(random.randint(MIN_LOGS, MAX_LOGS)):
        growth *= 1.05  # incremental growth simulation
        usage_logs.append(generate_usage_log(tier, growth))

    return {
        "_id": str(ObjectId()),
        "email": f"user{index}@example.com",
        "role": role,
        "subscription_tier": tier,
        "account_status": status,
        "usage_logs": usage_logs
    }

def inject_anomaly(users):
    """
    Inject a controlled anomaly:
    Add an extreme usage spike to one enterprise user.
    This enables anomaly detection testing later.
    """
    enterprise_users = [u for u in users if u["subscription_tier"] == "enterprise"]
    if enterprise_users:
        target = random.choice(enterprise_users)
        target["usage_logs"].append({
            "_id": str(ObjectId()),
            "api_calls": 120000,  # abnormal spike
            "storage_mb": 200000,
            "timestamp": datetime.utcnow().isoformat()
        })

def generate_dataset():
    """
    Generate full synthetic SaaS dataset.
    """
    users = [generate_user(i) for i in range(1, NUM_USERS + 1)]
    inject_anomaly(users)
    return users

if __name__ == "__main__":
    dataset = generate_dataset()

    # Export dataset to JSON file
    with open("seed_users.json", "w") as f:
        json.dump(dataset, f, indent=4)

    print("Advanced synthetic SaaS dataset generated successfully.")