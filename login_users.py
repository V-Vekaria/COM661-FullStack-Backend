from config import db
import bcrypt

login_collection = db["login"]

users = [
    {
        "email": "admin@example.com",
        "password": "admin123",
        "role": "admin"
    },
    {
        "email": "user@example.com",
        "password": "user123",
        "role": "user"
    }
]

for user in users:

    hashed = bcrypt.hashpw(
        user["password"].encode("utf-8"),
        bcrypt.gensalt()
    )

    login_collection.insert_one({
        "email": user["email"],
        "password": hashed,
        "role": user["role"]
    })

print("Login users created")