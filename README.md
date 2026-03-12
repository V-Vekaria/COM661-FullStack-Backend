# SaaS Usage Monitoring and Anomaly Detection API

A backend RESTful API built using Flask and MongoDB to simulate monitoring, analytics, and anomaly detection for a Software-as-a-Service (SaaS) platform.

This project was developed as part of the COM661 – Full Stack Development module at Ulster University.

The API allows administrators to manage users and monitor platform usage through structured usage logs.

---

## 🚀 Tech Stack

- Python 3.13
- Flask
- MongoDB Atlas (Cloud Database)
- PyMongo
- Flask Blueprints (modular API design)
- bcrypt (password hashing)
- dotenv for secure configuration
- Postman for API testing

---

## 📂 Project Structure

COM661_CW1_SAAS_API

│  
├── app.py  
├── config.py  
├── auth.py  
├── seed_data.py  
├── requirements.txt  
├── README.md  

│  
├── routes  
│   └── user.py  

│  
├── venv (not included in submission)  
└── __pycache__ (not included in submission)

---

## 📄 Description of Files

| File | Purpose |
|-----|------|
| app.py | Main Flask application entry point |
| config.py | MongoDB database configuration |
| auth.py | Handles authentication and authorization |
| seed_data.py | Generates sample data for the database |
| routes/user.py | Contains API routes for user management and usage logs |

---

## 🔐 Authentication

The API uses **Basic Authentication**.

Users must send their **email and password** in the request header.

Two roles exist in the system:

### Admin
Admins have full system access.

They can:

- Create users
- Delete users
- Add usage logs
- Delete usage logs

### User
Regular users can:

- View their profile
- Retrieve usage logs

Passwords are stored securely using **bcrypt hashing**.

---

## 🗄 Database Structure

Database name:

saas_monitoring

Collections used:

### users

Stores user profiles and their usage logs.

Example document:

{
  "_id": "ObjectId",
  "profile": {
    "email": "alice@cloudmetrics.io",
    "role": "user",
    "created_at": "2026-01-01"
  },
  "subscription": {
    "tier": "pro",
    "status": "active"
  },
  "usage_logs": [
    {
      "_id": "ObjectId",
      "timestamp": "2026-02-22",
      "metrics": {
        "api_calls": 396,
        "storage_mb": 4770
      },
      "request": {
        "endpoint": "/api/analytics",
        "region": "eu-west"
      }
    }
  ]
}

### login

Stores authentication credentials.

{
  "email": "admin@cloudmetrics.io",
  "password": "bcrypt_hash",
  "role": "admin",
  "user_id": "ObjectId"
}

---

## 📡 API Endpoints

### Health Check

| Method | Endpoint | Description |
|------|------|------|
| GET | /health | Check if API is running |

---

### User Management

| Method | Endpoint | Description | Access |
|------|------|------|------|
| POST | /users | Create a new user | Admin |
| GET | /users | Retrieve all users | Admin |
| GET | /users/{id} | Retrieve specific user | Authenticated |
| PUT | /users/{id} | Update user information | Authenticated |
| DELETE | /users/{id} | Delete a user | Admin |

---

### Usage Monitoring

| Method | Endpoint | Description | Access |
|------|------|------|------|
| POST | /users/{id}/usage | Add usage log | Admin |
| GET | /users/{id}/usage | Retrieve usage logs | Authenticated |
| DELETE | /users/{user_id}/usage/{log_id} | Delete usage log | Admin |

---

## 🧪 API Testing

The API was tested using **Postman**.

Testing includes:

- Authentication
- User CRUD operations
- Usage log creation
- Usage log retrieval
- Authorization checks
- Error handling

Automated tests were executed using the **Postman Collection Runner**.

---

## ⚙️ Running the Project

### 1. Install dependencies

pip install -r requirements.txt

---

### 2. Configure environment variables

Create a `.env` file with the MongoDB connection string.

Example:

MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net

---

### 3. Run the API

python app.py

Server will run at:

http://localhost:5001

---

## 📌 Example API Request

GET /users/{id}

Header:

Authorization: Basic base64(email:password)

Example response:

{
  "_id": "67e39a1b9c8d9a21",
  "profile": {
    "email": "alice@cloudmetrics.io",
    "role": "user"
  },
  "subscription": {
    "tier": "pro"
  }
}

---

## 📊 Coursework Context

This project demonstrates:

- REST API design
- MongoDB document database usage
- Authentication and role-based access control
- Modular Flask architecture using Blueprints
- API testing using Postman

Developed for **COM661 – Full Stack Development** at **Ulster University**.