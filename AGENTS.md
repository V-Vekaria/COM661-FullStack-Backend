# AGENTS.md

## Cursor Cloud specific instructions

### Overview

This is a Python Flask REST API for SaaS usage monitoring and anomaly detection, backed by MongoDB. There is no frontend — all interaction is via HTTP/JSON endpoints on port 5001.

### Services

| Service | Command | Port |
|---|---|---|
| MongoDB | `sudo rm -f /tmp/mongodb-27017.sock && mongod --dbpath /tmp/mongodb --fork --logpath /tmp/mongod.log` | 27017 |
| Flask API | `/workspace/.venv/bin/python app.py` | 5001 |

MongoDB must be running before starting the Flask API or seeding data.

### Virtual environment

Dependencies are installed in `/workspace/.venv`. Always use `/workspace/.venv/bin/python` to run scripts (or activate with `source /workspace/.venv/bin/activate`).

### Seeding the database

Run `python seed_data.py` (once) to populate the `saas_monitoring` database with 25 users, 4 operator accounts, 100 activity logs, and 35 anomaly flags. Operator password is `password123`.

### Gotchas

- `flask-cors` is imported in `app.py` but is **not** listed in `requirements.txt`. The update script installs it explicitly.
- The MongoDB connection string is **hardcoded** to `mongodb://localhost:27017` in `config.py` — no `.env` file is needed.
- The stale MongoDB socket file at `/tmp/mongodb-27017.sock` may need `sudo rm -f` before restarting `mongod`.
- There are **no automated tests** (no pytest, no test directory). Testing is done via HTTP requests (curl/Postman).
- The `SECRET_KEY` for JWT has a hardcoded fallback in `auth.py`, so no `.env` is required.

### Quick verification

```bash
curl http://localhost:5001/health
curl -X POST http://localhost:5001/login -H "Content-Type: application/json" \
  -d '{"email":"admin@cloudmetrics.io","password":"password123"}'
```
