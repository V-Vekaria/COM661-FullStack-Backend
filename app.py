from flask import Flask, jsonify
from routes.user import user_bp

app = Flask(__name__)

app.register_blueprint(user_bp)

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "API is running"}), 200

if __name__ == "__main__":
    app.run(debug=True, port=5001)
