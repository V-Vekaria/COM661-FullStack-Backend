from dotenv import load_dotenv
import os
from pymongo import MongoClient

load_dotenv()

print("Mongo URI inside config:", os.getenv("MONGO_URI"))

client = MongoClient(os.getenv("MONGO_URI"))
db = client["saas_monitoring"]