# SaaS Usage Monitoring and Anomaly Detection API

A backend RESTful API built with Python Flask and MongoDB to monitor, analyse, and detect anomalies across a SaaS platform's customer base.

Built for **COM661 – Full Stack Development** at Ulster University.

---

## Tech Stack

| Technology | Purpose |
|---|---|
| Python 3.13 | Runtime |
| Flask | Web framework |
| MongoDB Atlas / Local | Document database |
| PyMongo | MongoDB driver |
| Flask Blueprints | Modular route organisation |
| bcrypt | Password hashing |
| PyJWT | Token-based authentication |
| python-dotenv | Environment variable management |
| Flask-CORS | Cross-origin resource sharing |
| Postman | API testing |

---

## Project Structure

```
COM661_CW1_SAAS_API/
│
├── app.py               Main Flask entry point
├── auth.py              Authentication routes + JWT middleware decorators
├── config.py            MongoDB connection (reads from .env)
├── seed_data.py         Generates sample data for all collections
├── requirements.txt     Python dependencies
├── .env.example         Environment variable template
├── README.md
│
└── routes/
    ├── user.py          User, usage log, API key, alert, activity log, anomaly flag routes
    └── analytics.py     Aggregation pipeline endpoints + dashboard summary
```

---

## Running the Project

### 1. Install dependencies

```
pip install -r requirements.txt
```

### 2. Configure environment

Copy `.env.example` to `.env` and set your MongoDB URI:

```
MONGO_URI=mongodb://localhost:27017
SECRET_KEY=your-secret-key
```

### 3. Seed the database

```
python seed_data.py
```

### 4. Start the API

```
python app.py
```

Server runs at `http://localhost:5001`

---

## Authentication

The API uses **JWT (JSON Web Token)** authentication.

### Login

```
POST /login
Content-Type: application/json

{ "email": "admin@cloudmetrics.io", "password": "password123" }
```

Returns a token. Pass it in every subsequent request:

```
x-access-token: <token>
```

Tokens expire after **24 hours**.

---

## Roles and Permissions

Two operator roles exist. Monitored users (SaaS customers) are data — they do not log in.

| Role | Description |
|---|---|
| `admin` | Full create, read, update, delete access across all collections |
| `analyst` | Read-only access to analytics, logs, and flags. Can acknowledge alerts and add resolution notes |

### Seeded operator accounts (password: `password123`)

| Email | Role |
|---|---|
| admin@cloudmetrics.io | admin |
| admin2@cloudmetrics.io | admin |
| analyst@cloudmetrics.io | analyst |
| analyst2@cloudmetrics.io | analyst |

---

## Database Structure

Database name: `saas_monitoring`

### Collections

| Collection | Description |
|---|---|
| `users` | SaaS customers being monitored — contains embedded sub-documents |
| `login` | Operator credentials (admin + analyst accounts only) |
| `activity_logs` | Standalone audit records of user actions |
| `anomaly_flags` | Standalone anomaly records with embedded resolution sub-documents |

---

### Document Nesting Depth

The `users` collection demonstrates multiple levels of sub-document nesting:

```
users (level 1)
├── profile.*                                      (level 2 fields)
├── subscription.features_enabled.rate_limits.*    (level 4)
├── subscription.billing.payment_method.*          (level 4)
├── usage_logs[]                                   (level 2 sub-documents)
│   └── metrics.breakdown.*                        (level 4)
├── api_keys[]                                     (level 2 sub-documents)
└── alerts[]                                       (level 2 sub-documents)

anomaly_flags
├── resolution_logs[]                              (level 2 sub-documents)
└── evidence.suspicious_ips[]                      (level 3)

login
└── (operator credentials only)
```

---

### Example: users document

```json
{
  "_id": "ObjectId",
  "profile": {
    "first_name": "Alice",
    "last_name": "Smith",
    "email": "alice.smith0@cloudmetrics.io",
    "timezone": "UTC",
    "language": "en",
    "created_at": "2025-06-01T10:00:00",
    "last_login": "2026-04-01T08:30:00"
  },
  "subscription": {
    "tier": "pro",
    "status": "active",
    "billing_cycle": "monthly",
    "features_enabled": {
      "sso": false,
      "advanced_analytics": true,
      "rate_limits": {
        "requests_per_minute": 500,
        "burst_capacity": 1000,
        "throttle_enabled": true
      }
    },
    "billing": {
      "plan_price_usd": 29.99,
      "payment_method": {
        "type": "card",
        "last_four": "4242",
        "expires": "2027-12"
      }
    }
  },
  "usage_logs": [
    {
      "_id": "ObjectId",
      "timestamp": "2026-03-15T14:22:00",
      "metrics": {
        "api_calls": 4500,
        "storage_mb": 2048.5,
        "bandwidth_gb": 12.4,
        "active_sessions": 8,
        "breakdown": {
          "read_ops": 2700,
          "write_ops": 1400,
          "delete_ops": 400,
          "cache_hit_pct": 87.3
        }
      },
      "request": {
        "endpoint": "/api/analytics",
        "region": "eu-west",
        "method": "GET",
        "response_time_ms": 320,
        "status_code": 200
      },
      "location": { "type": "Point", "coordinates": [-0.1278, 51.5074] }
    }
  ],
  "api_keys": [
    {
      "_id": "ObjectId",
      "key_prefix": "sk_live_abc123de",
      "revoked": false,
      "permissions": ["read", "write"]
    }
  ],
  "alerts": [
    {
      "_id": "ObjectId",
      "alert_type": "threshold_breach",
      "message": "API call limit 90% reached",
      "severity": "high",
      "acknowledged": false
    }
  ],
  "metadata": {
    "industry": "fintech",
    "company_size": "51-200",
    "churn_risk": "medium",
    "nps_score": 8
  }
}
```

---

## API Endpoints

### Health Check

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | /health | None | API status check |

---

### Authentication

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /login | None | Obtain JWT token |
| GET | /me | Any | Current operator info from token |

---

### Users

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /users | admin | Create monitored user |
| GET | /users | admin | List users — paginated, filter by tier/status |
| GET | /users/search | admin | Search by email, tier, status, churn_risk, name |
| GET | /users/:id | admin | Get single user with all sub-documents |
| PUT | /users/:id | admin | Update user fields |
| DELETE | /users/:id | admin | Delete user + login record |

**Query params for GET /users:** `pn` (page), `ps` (page size), `tier`, `status`

**Query params for GET /users/search:** `email`, `first_name`, `last_name`, `tier` (comma-separated), `status`, `churn_risk`

---

### Usage Logs (sub-documents inside users)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /users/:id/usage | admin | Add usage log with metrics breakdown |
| GET | /users/:id/usage | admin, analyst | Get paginated usage logs |
| PUT | /users/:id/usage/:log_id | admin | Update usage log fields |
| DELETE | /users/:id/usage/:log_id | admin | Remove usage log |

---

### API Keys (sub-documents inside users)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /users/:id/api-keys | admin | Generate API key |
| GET | /users/:id/api-keys | admin, analyst | List API keys |
| PUT | /users/:id/api-keys/:key_id/revoke | admin | Revoke API key |
| DELETE | /users/:id/api-keys/:key_id | admin | Delete API key |

---

### Alerts (sub-documents inside users)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /users/:id/alerts | admin | Create alert |
| GET | /users/:id/alerts | admin, analyst | List alerts |
| PUT | /users/:id/alerts/:alert_id/acknowledge | admin, analyst | Acknowledge alert |
| DELETE | /users/:id/alerts/:alert_id | admin | Delete alert |

---

### Activity Logs (standalone collection)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /activity-logs | admin | Create activity log |
| GET | /activity-logs | admin, analyst | List logs — paginated, filterable |
| GET | /activity-logs/:id | admin, analyst | Get single log |
| PUT | /activity-logs/:id | admin | Update log fields |
| DELETE | /activity-logs/:id | admin | Delete log |

**Query params for GET /activity-logs:** `pn`, `ps`, `user_id`, `action_type`, `region`, `status_code`, `from`, `to`

---

### Anomaly Flags (standalone collection)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | /anomaly-flags | admin | Create anomaly flag |
| GET | /anomaly-flags | admin, analyst | List flags — paginated, filterable |
| GET | /anomaly-flags/:id | admin, analyst | Get single flag with resolution logs |
| PUT | /anomaly-flags/:id | admin | Update severity, resolved status, score |
| DELETE | /anomaly-flags/:id | admin | Delete flag |
| POST | /anomaly-flags/:id/resolve | admin, analyst | Add resolution log + mark resolved |
| DELETE | /anomaly-flags/:id/resolve/:res_id | admin | Delete resolution log |

**Query params for GET /anomaly-flags:** `pn`, `ps`, `severity`, `category`, `resolved`

---

### Analytics (aggregation pipelines)

All analytics endpoints require `admin` or `analyst` role.

| Method | Endpoint | Description | Pipeline operators used |
|---|---|---|---|
| GET | /dashboard/summary | Overview stats for frontend dashboard | `$group`, `$count` |
| GET | /analytics/avg-api-calls | Average + total API calls per user | `$unwind`, `$group`, `$project`, `$sort` |
| GET | /analytics/avg-api-calls-by-tier | API call stats grouped by subscription tier | `$unwind`, `$group`, `$project` |
| GET | /analytics/high-usage | Users exceeding API call threshold | `$unwind`, `$match`, `$project` |
| GET | /analytics/failed-logins | Users with repeated failed login attempts | `$match`, `$group`, `$sort` |
| GET | /analytics/anomaly-summary | Anomaly counts grouped by severity | `$group`, `$project` |
| GET | /analytics/search-logs | Multi-param filtered activity log search | `$match`, paginated |
| GET | /analytics/nearby-activity | Activity logs near a geo coordinate | `$geoNear`, `$project` |
| GET | /analytics/user-risk-report | Users joined with their anomaly flags | `$lookup`, `$project`, `$filter` |
| GET | /analytics/ops-breakdown | Read/write/delete ops breakdown by tier | `$unwind`, `$group` (queries level 4 nesting) |

**Query params:**

`/analytics/high-usage` — `threshold` (default 50000)

`/analytics/failed-logins` — `threshold` (default 3)

`/analytics/search-logs` — `action_types` (comma-separated), `regions` (comma-separated), `status_code`, `pn`, `ps`

`/analytics/nearby-activity` — `lat`, `lng`, `max_distance` (metres, default 5000000)

---

## Validation

All endpoints return consistent error responses:

```json
{ "error": "descriptive message", "field": "field_name" }
```

Validation applied across all endpoints:

| Check | Example |
|---|---|
| Required fields | Missing `email` → 400 |
| Email format | `notanemail` → 422 |
| Password length | Under 6 chars → 422 |
| Enum values | Invalid `severity` → 422 with allowed values listed |
| Numeric type | Non-integer `api_calls` → 422 |
| Range checks | `api_calls <= 0` → 422, `anomaly_score` outside 0.0–1.0 → 422 |
| HTTP status range | `status_code` outside 100–599 → 422 |
| Duplicate check | Existing email → 409 |

---

## Pagination

All list endpoints support pagination via query parameters:

| Param | Default | Description |
|---|---|---|
| `pn` | 1 | Page number |
| `ps` | 10 | Page size (max 100) |

Response shape:

```json
{
  "total": 25,
  "page": 1,
  "per_page": 10,
  "data": [...]
}
```

---

## HTTP Status Codes

| Code | Meaning |
|---|---|
| 200 | Success |
| 201 | Created |
| 400 | Bad request / missing required field |
| 401 | Missing or invalid token |
| 403 | Insufficient role permissions |
| 404 | Resource not found |
| 409 | Conflict (duplicate) |
| 422 | Validation error (type, range, enum) |