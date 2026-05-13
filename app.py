from flask import Flask
from config import get_db
from auth import auth_bp
from routes.users import users_bp
from routes.activity_logs import activity_bp
from routes.anomaly_flags import anomaly_bp
from routes.analytics import analytics_bp

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "saas-monitor-secret-key"

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(users_bp)
app.register_blueprint(activity_bp)
app.register_blueprint(anomaly_bp)
app.register_blueprint(analytics_bp)


@app.route("/health", methods=["GET"])
def health():
    return {"status": "running"}, 200


if __name__ == "__main__":
    app.run(port=5001, debug=True)