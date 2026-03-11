from pymongo import MongoClient

# MongoDB connection
client = MongoClient("mongodb://localhost:27017")

# Database used for the project
db = client["saas_monitoring"]