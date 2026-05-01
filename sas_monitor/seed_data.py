from datetime import datetime, timedelta
import random
import bcrypt
from config import client

db=client['sasDB']
assets,alerts,users=db['assets'],db['alerts'],db['users']
for c in [assets,alerts,users]: c.drop()

envs=['production','staging','dev']; regions=['eu-west-1','us-east-1','ap-south-1']; status=['online','degraded','offline']
sevs=['low','medium','high','critical']; atypes=['cpu_threshold','mem_threshold','disk_threshold','offline','session_limit']

for i in range(20):
    metrics=[{"recorded_at":datetime.utcnow()-timedelta(hours=j),"cpu_pct":round(random.uniform(20,99),1),"mem_pct":round(random.uniform(20,99),1),"disk_pct":round(random.uniform(20,99),1),"active_sessions":random.randint(0,200)} for j in range(5)]
    incidents=[{"incident_id":f"INC-{i}{k}","title":"Auto incident","severity":random.choice(sevs),"reported_by":"admin1","reported_at":datetime.utcnow()-timedelta(days=k),"resolved":False,"notes":"Generated"} for k in range(random.randint(2,3))]
    assets.insert_one({"name":f"prod-sas-{i:02d}","environment":random.choice(envs),"region":random.choice(regions),"os":"Linux","sas_version":"9.4","ip_address":f"10.0.{i//255}.{i%255}","status":random.choice(status),"added_by":"admin1","added_on":datetime.utcnow(),"tags":["critical"],"metrics":metrics,"incidents":incidents})

asset_names=[a['name'] for a in assets.find({}, {'name':1})]
for i in range(15):
    alerts.insert_one({"asset_id":random.choice(asset_names),"alert_type":random.choice(atypes),"threshold_value":90,"actual_value":round(random.uniform(90,100),1),"severity":random.choice(sevs),"triggered_at":datetime.utcnow()-timedelta(days=random.randint(0,30)),"acknowledged":False,"acknowledged_by":None})

users_data=[('Admin One','admin1','admin1@company.com','admin'),('Admin Two','admin2','admin2@company.com','admin'),('Engineer A','eng1','eng1@company.com','engineer'),('Engineer B','eng2','eng2@company.com','engineer'),('Engineer C','eng3','eng3@company.com','engineer')]
for n,u,e,r in users_data:
    users.insert_one({'name':n,'username':u,'password':bcrypt.hashpw('password123'.encode(), bcrypt.gensalt()).decode(),'email':e,'role':r})
print('Seed complete')
