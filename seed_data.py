from pymongo import MongoClient
import random
import bcrypt
import string
import os
from datetime import datetime, timedelta
from bson import ObjectId
from dotenv import load_dotenv

load_dotenv()

# CONFIG
NUM_USERS            = 20
NUM_ADMINS           = 3
NUM_ACTIVITY_LOGS    = 80
NUM_ANOMALY_FLAGS    = 30
USAGE_LOGS_PER_USER  = (3, 6)
API_KEYS_PER_USER    = (1, 3)
ALERTS_PER_USER      = (1, 3)
RESOLUTION_LOGS_PER_ANOMALY = (1, 3)

client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
db     = client[os.getenv("MONGO_DB_NAME", "saas_monitoring")]

users_col         = db["users"]
login_col         = db["login"]
activity_logs_col = db["activity_logs"]
anomaly_flags_col = db["anomaly_flags"]

# Drop old data
print("Dropping old collections...")
users_col.drop()
login_col.drop()
activity_logs_col.drop()
anomaly_flags_col.drop()
print("Seeding fresh data...\n")

# Reference data
REGIONS      = ["eu-west", "us-east", "us-west", "ap-south", "ap-northeast", "sa-east", "af-south"]
DEVICE_TYPES = ["desktop", "mobile", "tablet", "server", "cli"]
ENDPOINTS    = [
    "/api/upload", "/api/download", "/api/users", "/api/analytics",
    "/api/reports", "/api/billing", "/api/settings", "/api/export", "/api/alerts"
]
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
ACTION_TYPES = [
    "login", "logout", "upload", "download", "delete", "create", "update",
    "export", "failed_login", "password_reset", "api_key_generate",
    "billing_view", "report_generate", "settings_update"
]
SUBSCRIPTION_TIERS = ["free", "pro", "enterprise"]
ACCOUNT_STATUSES   = ["active", "suspended", "inactive", "pending_verification"]
ROLES              = ["admin", "analyst"]
ANOMALY_REASONS    = [
    "Excessive failed logins",
    "Unusual API call volume spike",
    "Access from multiple countries within 1 hour",
    "Bulk data export outside business hours",
    "Repeated access to restricted endpoint",
    "IP address flagged in threat database",
    "Account accessed from new device/region simultaneously",
    "Abnormally high storage consumption",
    "API key used after revocation attempt",
    "Suspicious billing query pattern",
]
RESOLUTION_NOTES = [
    "Investigated — confirmed false positive due to VPN usage.",
    "User contacted and confirmed legitimate activity.",
    "Account temporarily suspended pending review.",
    "IP whitelisted after verification.",
    "Escalated to security team for further analysis.",
    "User acknowledged bulk export was intentional.",
    "Resolved after MFA re-enforcement.",
    "No further action required after audit.",
]
RESOLUTION_ACTIONS = ["whitelisted", "suspended", "password_reset", "mfa_enforced", "no_action", "escalated"]
REGION_COORDS = {
    "eu-west":      {"type": "Point", "coordinates": [-0.1278,   51.5074]},
    "us-east":      {"type": "Point", "coordinates": [-77.0369,  38.9072]},
    "us-west":      {"type": "Point", "coordinates": [-122.4194, 37.7749]},
    "ap-south":     {"type": "Point", "coordinates": [72.8777,   19.0760]},
    "ap-northeast": {"type": "Point", "coordinates": [139.6917,  35.6895]},
    "sa-east":      {"type": "Point", "coordinates": [-46.6333, -23.5505]},
    "af-south":     {"type": "Point", "coordinates": [18.4241,  -33.9249]},
}
COMPANY_DOMAINS = [
    "cloudmetrics.io", "saasplatform.net", "techcorp.com",
    "innovatesys.co", "databridge.io", "nexusops.com", "skylabs.tech"
]
FIRST_NAMES = [
    "Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry",
    "Iris", "James", "Karen", "Liam", "Maya", "Noah", "Olivia", "Paul",
    "Quinn", "Rachel", "Sam", "Tara"
]
LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Patel", "Nguyen", "Kim", "Chen", "Singh"
]
SEVERITIES  = ["low", "medium", "high", "critical"]
CATEGORIES  = ["security", "performance", "billing", "compliance"]
PERMISSIONS = ["read", "write", "delete", "admin", "billing"]


def random_date(days_ago_max=180, days_ago_min=0):
    now   = datetime.utcnow()
    start = now - timedelta(days=days_ago_max)
    end   = now - timedelta(days=days_ago_min)
    delta = (end - start).total_seconds()
    return start + timedelta(seconds=random.random() * delta)


def fake_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def rand_str(length=12):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def hash_pw(raw="password123"):
    return bcrypt.hashpw(raw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def generate_usage_logs():
    logs = []
    for _ in range(random.randint(*USAGE_LOGS_PER_USER)):
        region = random.choice(REGIONS)
        api_calls = random.randint(100, 100000)
        logs.append({
            "_id":       ObjectId(),
            "timestamp": random_date(90),
            "metrics": {
                "api_calls":  api_calls,
                "storage_mb": round(random.uniform(10, 10000), 2),
                "breakdown": {
                    "reads":  int(api_calls * 0.6),
                    "writes": int(api_calls * 0.4),
                },
            },
            "request": {
                "endpoint":         random.choice(ENDPOINTS),
                "region":           region,
                "method":           random.choice(HTTP_METHODS),
                "response_time_ms": random.randint(50, 5000),
                "status_code":      random.choice([200, 200, 200, 201, 400, 401, 404, 500]),
            },
            "location": REGION_COORDS[region],
        })
    return logs


def generate_api_keys(tier):
    keys = []
    env = "live" if tier != "free" else "test"
    for _ in range(random.randint(*API_KEYS_PER_USER)):
        keys.append({
            "_id":         ObjectId(),
            "key_prefix":  f"sk_{env}_{rand_str(8)}",
            "created_at":  random_date(300, 10),
            "last_used":   random_date(10),
            "revoked":     random.choice([False, False, False, True]),
            "permissions": random.sample(PERMISSIONS, k=random.randint(1, 4)),
        })
    return keys


def generate_alerts():
    alerts = []
    for _ in range(random.randint(*ALERTS_PER_USER)):
        alerts.append({
            "_id":          ObjectId(),
            "alert_type":   random.choice(["threshold_breach", "security_event", "billing_alert", "performance_degradation"]),
            "message":      random.choice(["API call limit 90% reached", "Storage quota exceeded", "Unusual login location detected"]),
            "severity":     random.choice(SEVERITIES),
            "triggered_at": random_date(60),
            "acknowledged": random.choice([True, False]),
        })
    return alerts


def generate_resolution_logs(admin_ids, admin_emails):
    logs = []
    for _ in range(random.randint(*RESOLUTION_LOGS_PER_ANOMALY)):
        idx = random.randint(0, len(admin_ids) - 1)
        logs.append({
            "_id":          ObjectId(),
            "admin_id":     admin_ids[idx],
            "admin_email":  admin_emails[idx],
            "note":         random.choice(RESOLUTION_NOTES),
            "action_taken": random.choice(RESOLUTION_ACTIONS),
            "timestamp":    random_date(60),
        })
    return logs


# Seed operator accounts (used by Postman to log in)
# These are in the login collection only — they are the API operators
operator_accounts = [
    {"email": "admin@cloudmetrics.io",    "role": "admin",    "password": "password123"},
    {"email": "analyst@cloudmetrics.io",  "role": "analyst",  "password": "password123"},
]

for op in operator_accounts:
    op_id = ObjectId()
    login_col.insert_one({
        "email":    op["email"],
        "password": hash_pw(op["password"]),
        "role":     op["role"],
        "user_id":  str(op_id),
    })

print(f"  ✓ operator accounts seeded (admin + analyst)")

# Seed monitored users
user_ids    = []
user_emails = []

for i in range(NUM_USERS):
    fname  = FIRST_NAMES[i % len(FIRST_NAMES)]
    lname  = random.choice(LAST_NAMES)
    domain = random.choice(COMPANY_DOMAINS)
    email  = f"{fname.lower()}.{lname.lower()}{i}@{domain}"
    role   = "admin" if i < NUM_ADMINS else random.choice(ROLES)
    tier   = random.choice(SUBSCRIPTION_TIERS)
    status = "active" if i < NUM_ADMINS else random.choice(ACCOUNT_STATUSES)

    user_id = ObjectId()
    user_ids.append(user_id)
    user_emails.append(email)

    user_doc = {
        "_id": user_id,
        "profile": {
            "first_name": fname,
            "last_name":  lname,
            "email":      email,
            "role":       role,
            "created_at": random_date(400, 200),
            "last_login": random_date(30),
        },
        "subscription": {
            "tier":   tier,
            "status": status,
        },
        "usage_logs": generate_usage_logs(),
        "api_keys":   generate_api_keys(tier),
        "alerts":     generate_alerts(),
        "metadata": {
            "churn_risk": random.choice(["low", "medium", "high"]),
            "industry":   random.choice(["fintech", "healthtech", "ecommerce", "logistics"]),
        },
    }
    users_col.insert_one(user_doc)

    login_col.insert_one({
        "email":    email,
        "password": hash_pw(),
        "role":     role,
        "user_id":  str(user_id),
    })

print(f"  ✓ users         — {users_col.count_documents({})} documents inserted")
print(f"  ✓ login         — {login_col.count_documents({})} documents inserted")

# Seed activity logs
admin_ids    = user_ids[:NUM_ADMINS]
admin_emails = user_emails[:NUM_ADMINS]

activity_docs = []
for _ in range(NUM_ACTIVITY_LOGS):
    idx    = random.randint(0, NUM_USERS - 1)
    region = random.choice(REGIONS)
    activity_docs.append({
        "user_id":    str(user_ids[idx]),
        "user_email": user_emails[idx],
        "action_type": random.choice(ACTION_TYPES),
        "network": {
            "ip_address":  fake_ip(),
            "device_type": random.choice(DEVICE_TYPES),
            "region":      region,
            "location":    REGION_COORDS[region],
        },
        "performance": {
            "response_time_ms":  random.randint(20, 8000),
            "status_code":       random.choice([200, 200, 201, 204, 400, 401, 403, 404, 500]),
            "bytes_transferred": random.randint(128, 10485760),
        },
        "timestamp":  random_date(180),
        "session_id": rand_str(16),
    })

activity_logs_col.insert_many(activity_docs)
# Create geo index for nearby-activity endpoint
activity_logs_col.create_index([("network.location", "2dsphere")])
print(f"  ✓ activity_logs — {activity_logs_col.count_documents({})} documents inserted")

# Seed anomaly flags
anomaly_docs = []
for _ in range(NUM_ANOMALY_FLAGS):
    idx      = random.randint(0, NUM_USERS - 1)
    resolved = random.choice([True, False])
    anomaly_docs.append({
        "user_id":       str(user_ids[idx]),
        "user_email":    user_emails[idx],
        "reason":        random.choice(ANOMALY_REASONS),
        "anomaly_score": round(random.uniform(0.3, 1.0), 4),
        "severity":      random.choice(SEVERITIES),
        "category":      random.choice(CATEGORIES),
        "detected_at":   random_date(120),
        "resolved":      resolved,
        "resolution_logs": generate_resolution_logs(admin_ids, admin_emails) if resolved else [],
        "evidence": {
            "failed_login_count": random.randint(0, 30),
            "suspicious_ips":     [fake_ip() for _ in range(random.randint(1, 3))],
        },
    })

anomaly_flags_col.insert_many(anomaly_docs)
print(f"  ✓ anomaly_flags — {anomaly_flags_col.count_documents({})} documents inserted")

print("\nDatabase seeded successfully!")
print("  Operator logins: admin@cloudmetrics.io / analyst@cloudmetrics.io (password: password123)")
