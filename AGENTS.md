# AGENTS.md

## Cursor Cloud specific instructions

### Overview

This is a **backend-only REST API** (Python Flask + MongoDB) for SaaS usage monitoring and anomaly detection. There is no frontend — testing is done via `curl` or Postman against `http://localhost:5001`.

### Services

| Service | How to start | Port/Address |
|---|---|---|
| MongoDB | `mongod --dbpath /data/db --fork --logpath /var/log/mongod.log` | `localhost:27017` |
| Flask API | `source /workspace/venv/bin/activate && python3 app.py` | `localhost:5001` |

MongoDB **must** be running before the Flask app starts. The connection string is hardcoded in `config.py` to `mongodb://localhost:27017`.

### Key gotchas

- **Missing dependency**: `flask-cors` is imported in `app.py` but is **not** listed in `requirements.txt`. The update script installs it separately.
- **PyJWT conflict**: The system Python ships a Debian-managed `PyJWT 2.7.0` that cannot be uninstalled via pip. Use the virtualenv at `/workspace/venv` to avoid this conflict.
- **No `.env` file needed**: Despite the README mentioning `.env.example`, the code hardcodes the MongoDB URI and `SECRET_KEY` has a default fallback in `auth.py`.
- **No automated tests**: The project has no test suite or test framework.
- **No linter configured**: No linting tools (flake8, pylint, ruff, etc.) are configured in the project.
- **Seed data**: Run `python3 seed_data.py` (with venv activated) to populate MongoDB with sample data. This drops and recreates all collections.

### Running the API

```bash
source /workspace/venv/bin/activate
python3 app.py
```

### Seeded operator accounts (password: `password123`)

| Email | Role |
|---|---|
| admin@cloudmetrics.io | admin |
| admin2@cloudmetrics.io | admin |
| analyst@cloudmetrics.io | analyst |
| analyst2@cloudmetrics.io | analyst |

### Authentication

```bash
# Get a JWT token
TOKEN=$(curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cloudmetrics.io","password":"password123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Use the token
curl -s http://localhost:5001/users -H "x-access-token: $TOKEN"
```

See `README.md` for the full list of API endpoints.
