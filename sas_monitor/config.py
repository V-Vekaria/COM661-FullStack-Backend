import os
from pymongo import MongoClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
DB_NAME = os.getenv("DB_NAME", "sasDB")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production")

ALLOWED_ENVIRONMENTS = ["production", "staging", "dev"]
ALLOWED_STATUS = ["online", "degraded", "offline"]
ALLOWED_SEVERITY = ["low", "medium", "high", "critical"]
ALLOWED_ALERT_TYPES = ["cpu_threshold", "mem_threshold", "disk_threshold", "offline", "session_limit"]

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
