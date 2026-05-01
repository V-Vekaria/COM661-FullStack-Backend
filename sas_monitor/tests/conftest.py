import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))
import pytest
import bcrypt
from app import create_app
from config import client as mongo_client

@pytest.fixture
def app():
    test_db=mongo_client['sasDB_test']
    for c in ['users','assets','alerts']:
        test_db[c].drop()
    test_db['users'].insert_many([
        {'name':'Admin','username':'admin','password':bcrypt.hashpw('pass'.encode(),bcrypt.gensalt()).decode(),'email':'admin@x.com','role':'admin'},
        {'name':'Eng','username':'eng','password':bcrypt.hashpw('pass'.encode(),bcrypt.gensalt()).decode(),'email':'eng@x.com','role':'engineer'}
    ])
    aid=test_db['assets'].insert_one({'name':'prod-sas-01','environment':'production','region':'eu-west-1','os':'Linux','sas_version':'9.4','ip_address':'10.0.0.1','status':'online','added_by':'admin','added_on':None,'tags':[],'metrics':[],'incidents':[]}).inserted_id
    test_db['alerts'].insert_one({'asset_id':str(aid),'alert_type':'cpu_threshold','threshold_value':90,'actual_value':95,'severity':'critical','triggered_at':None,'acknowledged':False,'acknowledged_by':None})
    import config
    config.db = test_db
    from blueprints import auth,assets,alerts
    auth.users=test_db['users']; assets.assets=test_db['assets']; alerts.alerts=test_db['alerts']
    app=create_app({'TESTING':True,'JWT_SECRET_KEY':'test-secret'})
    yield app
    mongo_client.drop_database('sasDB_test')

@pytest.fixture
def client(app):
    return app.test_client()

def token_for(client, username='admin', password='pass'):
    r=client.post('/api/auth/login', json={'username':username,'password':password})
    return r.get_json()['data']['token']
