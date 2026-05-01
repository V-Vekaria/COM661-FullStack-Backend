import bcrypt
from config import db

users=db['users']
raw=[('Temp Admin','tempadmin','tempadmin@company.com','admin'),('Temp Engineer','tempeng','tempeng@company.com','engineer')]
for n,u,e,r in raw:
    if users.find_one({'username':u}):
        continue
    users.insert_one({'name':n,'username':u,'password':bcrypt.hashpw('password123'.encode(),bcrypt.gensalt()).decode(),'email':e,'role':r})
print('Users ensured')
