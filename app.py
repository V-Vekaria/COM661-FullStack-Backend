from flask import Flask, jsonify
from routes.user import user_bp
from auth import auth_bp  # Import auth blueprint

app = Flask(__name__)

# Register blueprints
app.register_blueprint(user_bp)
app.register_blueprint(auth_bp)

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "API is running"}), 200

if __name__ == "__main__":
    app.run(debug=True, port=5001)