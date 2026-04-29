import random
import bcrypt
import string
from datetime import datetime, timedelta
from bson import ObjectId
from pymongo import MongoClient

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

NUM_USERS                   = 25
NUM_ACTIVITY_LOGS           = 100
NUM_ANOMALY_FLAGS            = 35
USAGE_LOGS_PER_USER         = (3, 7)
API_KEYS_PER_USER           = (1, 3)
ALERTS_PER_USER             = (1, 3)
RESOLUTION_LOGS_PER_ANOMALY = (1, 3)

client = MongoClient("mongodb://localhost:27017/")
db     = client["saas_monitoring"]

users_col         = db["users"]
login_col         = db["login"]
activity_logs_col = db["activity_logs"]
anomaly_flags_col = db["anomaly_flags"]

print("Dropping old collections...")
users_col.drop()
login_col.drop()
activity_logs_col.drop()
anomaly_flags_col.drop()
print("Collections dropped. Seeding fresh data...\n")

# ---------------------------------------------------------------------------
# REFERENCE DATA
# ---------------------------------------------------------------------------

REGIONS      = ["eu-west", "us-east", "us-west", "ap-south", "ap-northeast", "sa-east", "af-south"]
DEVICE_TYPES = ["desktop", "mobile", "tablet", "server", "cli"]
ENDPOINTS    = [
    "/api/upload", "/api/download", "/api/users", "/api/analytics",
    "/api/reports", "/api/billing", "/api/settings", "/api/export", "/api/alerts",
]
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
ACTION_TYPES = [
    "login", "logout", "upload", "download", "delete", "create", "update",
    "export", "failed_login", "password_reset", "api_key_generate",
    "billing_view", "report_generate", "settings_update",
]
SUBSCRIPTION_TIERS = ["free", "pro", "enterprise"]
ACCOUNT_STATUSES   = ["active", "suspended", "inactive", "pending_verification"]
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
REGION_COORDS      = {
    "eu-west":      {"type": "Point", "coordinates": [-0.1278,    51.5074]},
    "us-east":      {"type": "Point", "coordinates": [-77.0369,   38.9072]},
    "us-west":      {"type": "Point", "coordinates": [-122.4194,  37.7749]},
    "ap-south":     {"type": "Point", "coordinates": [72.8777,    19.0760]},
    "ap-northeast": {"type": "Point", "coordinates": [139.6917,   35.6895]},
    "sa-east":      {"type": "Point", "coordinates": [-46.6333,  -23.5505]},
    "af-south":     {"type": "Point", "coordinates": [18.4241,   -33.9249]},
}
COMPANY_DOMAINS = [
    "cloudmetrics.io", "saasplatform.net", "techcorp.com",
    "innovatesys.co", "databridge.io", "nexusops.com", "skylabs.tech",
]
FIRST_NAMES = [
    "Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry",
    "Iris", "James", "Karen", "Liam", "Maya", "Noah", "Olivia", "Paul",
    "Quinn", "Rachel", "Sam", "Tara", "Ulrich", "Vera", "Walter", "Xena", "Yusuf",
]
LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Patel", "Nguyen", "Kim", "Chen", "Singh",
]
USER_AGENTS   = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "python-requests/2.28.0",
    "CloudMetrics-CLI/1.4.2",
    "okhttp/4.9.0",
]
RESOURCE_TYPES  = ["file", "report", "user", "api_key", "dashboard", "dataset"]
RESOURCE_NAMES  = ["Q4_report.csv", "user_export.json", "analytics_dashboard", "billing_record", "audit_log"]
ALERT_TYPES     = ["threshold_breach", "security_event", "billing_alert", "performance_degradation"]
ALERT_MESSAGES  = [
    "API call limit 90% reached",
    "Storage quota exceeded",
    "Unusual login location detected",
    "Billing payment failed",
    "Response time degraded",
]
INDUSTRIES      = ["fintech", "healthtech", "ecommerce", "logistics", "media", "edtech", "hr_tech"]
COMPANY_SIZES   = ["1-10", "11-50", "51-200", "201-1000", "1000+"]
SIGNUP_SOURCES  = ["organic", "referral", "paid_ad", "partner", "trial"]
SEVERITIES      = ["low", "medium", "high", "critical"]
CATEGORIES      = ["security", "performance", "billing", "compliance"]
COUNTRIES       = ["UK", "US", "IN", "JP", "BR", "DE", "FR", "AU"]
PERMISSIONS     = ["read", "write", "delete", "admin", "billing"]
TIMEZONES       = ["UTC", "America/New_York", "Europe/London", "Asia/Tokyo", "Asia/Mumbai"]
LANGUAGES       = ["en", "es", "fr", "de", "ja", "pt"]


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

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


def hash_password(raw="password123"):
    return bcrypt.hashpw(raw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


# ---------------------------------------------------------------------------
# SUB-DOCUMENT BUILDERS
# ---------------------------------------------------------------------------

def generate_usage_logs():
    """Usage logs with 4-level deep nesting: metrics.breakdown.*"""
    logs = []
    for _ in range(random.randint(*USAGE_LOGS_PER_USER)):
        region    = random.choice(REGIONS)
        api_calls = random.randint(100, 100_000)
        logs.append({
            "_id":       ObjectId(),
            "timestamp": random_date(90),
            "metrics": {
                "api_calls":       api_calls,
                "storage_mb":      round(random.uniform(10, 10_000), 2),
                "bandwidth_gb":    round(random.uniform(0.1, 500), 2),
                "active_sessions": random.randint(1, 50),
                "breakdown": {                              # level 4
                    "read_ops":      int(api_calls * random.uniform(0.5, 0.7)),
                    "write_ops":     int(api_calls * random.uniform(0.2, 0.35)),
                    "delete_ops":    int(api_calls * random.uniform(0.01, 0.1)),
                    "cache_hit_pct": round(random.uniform(40, 99), 1),
                },
            },
            "request": {
                "endpoint":         random.choice(ENDPOINTS),
                "region":           region,
                "method":           random.choice(HTTP_METHODS),
                "response_time_ms": random.randint(50, 5_000),
                "status_code":      random.choice([200, 200, 200, 201, 400, 401, 403, 404, 500]),
            },
            "location": REGION_COORDS[region],
        })
    return logs


def generate_api_keys(tier):
    keys = []
    for _ in range(random.randint(*API_KEYS_PER_USER)):
        env = "live" if tier != "free" else "test"
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
            "alert_type":   random.choice(ALERT_TYPES),
            "message":      random.choice(ALERT_MESSAGES),
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


# ---------------------------------------------------------------------------
# SEED OPERATORS — admin + analyst accounts in login collection
# ---------------------------------------------------------------------------

OPERATOR_ACCOUNTS = [
    {"email": "admin@cloudmetrics.io",   "role": "admin"},
    {"email": "admin2@cloudmetrics.io",  "role": "admin"},
    {"email": "analyst@cloudmetrics.io", "role": "analyst"},
    {"email": "analyst2@cloudmetrics.io","role": "analyst"},
]

operator_ids    = []
operator_emails = []

for op in OPERATOR_ACCOUNTS:
    op_id = ObjectId()
    operator_ids.append(op_id)
    operator_emails.append(op["email"])
    login_col.insert_one({
        "email":               op["email"],
        "password":            hash_password("password123"),
        "role":                op["role"],
        "user_id":             str(op_id),
        "failed_attempts":     0,
        "last_password_change": random_date(180, 10),
    })

print(f"  ✓ operators     — {len(OPERATOR_ACCOUNTS)} login accounts seeded (2 admin, 2 analyst)")

admin_ids    = [oid for oid, op in zip(operator_ids, OPERATOR_ACCOUNTS) if op["role"] == "admin"]
admin_emails = [op["email"] for op in OPERATOR_ACCOUNTS if op["role"] == "admin"]


# ---------------------------------------------------------------------------
# SEED MONITORED USERS (SaaS customers — data, not system operators)
# ---------------------------------------------------------------------------

user_ids    = []
user_emails = []

for i in range(NUM_USERS):
    fname  = FIRST_NAMES[i % len(FIRST_NAMES)]
    lname  = random.choice(LAST_NAMES)
    domain = random.choice(COMPANY_DOMAINS)
    email  = f"{fname.lower()}.{lname.lower()}{i}@{domain}"
    tier   = random.choice(SUBSCRIPTION_TIERS)
    status = random.choice(ACCOUNT_STATUSES)

    user_id = ObjectId()
    user_ids.append(user_id)
    user_emails.append(email)

    user_doc = {
        "_id": user_id,
        "profile": {
            "first_name": fname,
            "last_name":  lname,
            "email":      email,
            "phone":      f"+{random.randint(1,99)}{random.randint(1_000_000_000, 9_999_999_999)}",
            "created_at": random_date(400, 200),
            "last_login": random_date(30),
            "avatar_url": f"https://cdn.cloudmetrics.io/avatars/{fname.lower()}_{i+1}.png",
            "timezone":   random.choice(TIMEZONES),
            "language":   random.choice(LANGUAGES),
        },
        "subscription": {
            "tier":           tier,
            "status":         status,
            "billing_cycle":  random.choice(["monthly", "annual"]),
            "renewal_date":   random_date(90, 1),
            "seats_allocated": (
                random.randint(1, 50) if tier == "enterprise"
                else random.randint(1, 5) if tier == "pro"
                else 1
            ),
            "features_enabled": {
                "sso":                tier == "enterprise",
                "advanced_analytics": tier in ("pro", "enterprise"),
                "priority_support":   tier in ("pro", "enterprise"),
                "audit_logs":         tier == "enterprise",
                "custom_domains":     tier == "enterprise",
                "rate_limits": {                            # level 3
                    "requests_per_minute": 100 if tier == "free" else (500 if tier == "pro" else 2000),
                    "burst_capacity":      200 if tier == "free" else (1000 if tier == "pro" else 5000),
                    "throttle_enabled":    tier != "free",
                },
            },
            "billing": {                                    # nested inside subscription
                "plan_price_usd": 0 if tier == "free" else (29.99 if tier == "pro" else 199.99),
                "payment_method": {                         # level 4
                    "type":      random.choice(["card", "bank_transfer", "paypal"]) if tier != "free" else None,
                    "last_four": str(random.randint(1000, 9999)) if tier != "free" else None,
                    "expires":   "2027-12" if tier != "free" else None,
                },
            },
        },
        "usage_logs": generate_usage_logs(),
        "api_keys":   generate_api_keys(tier),
        "alerts":     generate_alerts(),
        "metadata": {
            "signup_source": random.choice(SIGNUP_SOURCES),
            "industry":      random.choice(INDUSTRIES),
            "company_size":  random.choice(COMPANY_SIZES),
            "nps_score":     random.randint(1, 10) if random.random() > 0.3 else None,
            "churn_risk":    random.choice(["low", "medium", "high"]),
        },
    }
    users_col.insert_one(user_doc)

print(f"  ✓ users         — {users_col.count_documents({})} monitored users inserted")


# ---------------------------------------------------------------------------
# SEED ACTIVITY LOGS
# ---------------------------------------------------------------------------

activity_docs = []
for _ in range(NUM_ACTIVITY_LOGS):
    idx    = random.randint(0, NUM_USERS - 1)
    region = random.choice(REGIONS)
    activity_docs.append({
        "user_id":     user_ids[idx],
        "user_email":  user_emails[idx],
        "action_type": random.choice(ACTION_TYPES),
        "resource": {
            "id":   rand_str(12),
            "type": random.choice(RESOURCE_TYPES),
            "name": random.choice(RESOURCE_NAMES),
        },
        "network": {
            "ip_address":  fake_ip(),
            "device_type": random.choice(DEVICE_TYPES),
            "user_agent":  random.choice(USER_AGENTS),
            "region":      region,
            "location":    REGION_COORDS[region],
        },
        "performance": {
            "response_time_ms":  random.randint(20, 8_000),
            "status_code":       random.choice([200, 200, 200, 201, 204, 400, 401, 403, 404, 429, 500]),
            "bytes_transferred": random.randint(128, 10_485_760),
        },
        "timestamp":  random_date(180),
        "session_id": rand_str(16),
    })

activity_logs_col.insert_many(activity_docs)
print(f"  ✓ activity_logs — {activity_logs_col.count_documents({})} documents inserted")


# ---------------------------------------------------------------------------
# SEED ANOMALY FLAGS
# ---------------------------------------------------------------------------

anomaly_docs = []
for _ in range(NUM_ANOMALY_FLAGS):
    idx      = random.randint(0, NUM_USERS - 1)
    resolved = random.choice([True, False])
    anomaly_docs.append({
        "user_id":    user_ids[idx],
        "user_email": user_emails[idx],
        "reason":     random.choice(ANOMALY_REASONS),
        "anomaly_score": round(random.uniform(0.3, 1.0), 4),
        "severity":   random.choice(SEVERITIES),
        "category":   random.choice(CATEGORIES),
        "detected_at": random_date(120),
        "resolved":   resolved,
        "resolution_logs": (
            generate_resolution_logs(admin_ids, admin_emails) if resolved else []
        ),
        "evidence": {
            "failed_login_count": random.randint(0, 30),
            "countries_accessed": random.sample(COUNTRIES, k=random.randint(1, 4)),
            "suspicious_ips":     [fake_ip() for _ in range(random.randint(1, 3))],
            "time_window_hours":  random.choice([1, 6, 12, 24, 48]),
            "flagged_endpoints":  random.sample(ENDPOINTS, k=random.randint(1, 3)),
        },
        "auto_actions_taken": {
            "account_locked":    random.choice([True, False]),
            "notification_sent": True,
            "admin_alerted":     random.choice([True, False]),
        },
    })

anomaly_flags_col.insert_many(anomaly_docs)
print(f"  ✓ anomaly_flags — {anomaly_flags_col.count_documents({})} documents inserted")

# ---------------------------------------------------------------------------
# DONE
# ---------------------------------------------------------------------------

print("\nDatabase seeded successfully.")
print("  Database    : saas_monitoring")
print("  Collections : users, login, activity_logs, anomaly_flags")
print("\nOperator accounts (all password: password123):")
for op in OPERATOR_ACCOUNTS:
    print(f"  {op['role']:8}  {op['email']}")