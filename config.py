from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

_client = None
_db = None


def get_db():
    global _client, _db
    if _db is None:
        _client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
        _db = _client[os.getenv("MONGO_DB_NAME", "saas_monitoring")]
    return _db
