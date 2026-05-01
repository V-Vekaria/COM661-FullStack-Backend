from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from blueprints.auth import auth_bp
from blueprints.assets import assets_bp
from blueprints.alerts import alerts_bp
from config import JWT_SECRET_KEY


def create_app(test_config=None):
    """Create and configure Flask application instance."""
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
    if test_config:
        app.config.update(test_config)
    JWTManager(app)

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(assets_bp, url_prefix="/api/assets")
    app.register_blueprint(alerts_bp, url_prefix="/api/alerts")

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"message": "ok"}), 200

    return app


if __name__ == "__main__":
    create_app().run(debug=True)
