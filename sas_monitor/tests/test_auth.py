def test_register_user(client):
    r=client.post('/api/auth/register',json={'name':'n','username':'u1','password':'p','email':'u1@x.com'})
    assert r.status_code==201

def test_register_duplicate(client):
    client.post('/api/auth/register',json={'name':'n','username':'dupe','password':'p','email':'a@x.com'})
    r=client.post('/api/auth/register',json={'name':'n','username':'dupe','password':'p','email':'b@x.com'})
    assert r.status_code==409

def test_login_valid(client):
    r=client.post('/api/auth/login',json={'username':'admin','password':'pass'})
    assert r.status_code==200 and 'token' in r.get_json()['data']

def test_login_invalid_password(client):
    r=client.post('/api/auth/login',json={'username':'admin','password':'bad'})
    assert r.status_code==401
