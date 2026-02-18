from flask import Flask, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv
import os
load_dotenv()

load_dotenv()

app = Flask(__name__)

from routes.user import user_bp
app.register_blueprint(user_bp)

client = MongoClient(os.getenv("MONGO_URI"))
db = client["saas_monitoring"]

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "API is running"}), 200

if __name__ == "__main__":
    app.run(debug=True, port=5001)
