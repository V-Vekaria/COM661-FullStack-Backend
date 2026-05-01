from tests.conftest import token_for

def test_get_all_assets(client):
    assert client.get('/api/assets').status_code==200

def test_get_single_asset(client):
    aid=client.get('/api/assets').get_json()['data'][0]['_id']
    assert client.get(f'/api/assets/{aid}').status_code==200

def test_get_nonexistent_asset(client):
    assert client.get('/api/assets/000000000000000000000000').status_code==404

def test_create_asset_auth(client):
    t=token_for(client)
    r=client.post('/api/assets',headers={'Authorization':f'Bearer {t}'},json={'name':'n','environment':'production','region':'eu-west-1','os':'Linux','sas_version':'9.4','ip_address':'10.0.0.2','status':'online'})
    assert r.status_code==201

def test_create_asset_missing_field(client):
    t=token_for(client)
    assert client.post('/api/assets',headers={'Authorization':f'Bearer {t}'},json={'name':'n'}).status_code==400

def test_create_asset_invalid_status(client):
    t=token_for(client)
    r=client.post('/api/assets',headers={'Authorization':f'Bearer {t}'},json={'name':'n','environment':'production','region':'eu-west-1','os':'Linux','sas_version':'9.4','ip_address':'10.0.0.2','status':'bad'})
    assert r.status_code==400

def test_update_asset(client):
    t=token_for(client)
    aid=client.get('/api/assets').get_json()['data'][0]['_id']
    assert client.put(f'/api/assets/{aid}',headers={'Authorization':f'Bearer {t}'},json={'status':'degraded'}).status_code==200

def test_delete_asset_admin(client):
    t=token_for(client,'admin','pass'); aid=client.get('/api/assets').get_json()['data'][0]['_id']
    assert client.delete(f'/api/assets/{aid}',headers={'Authorization':f'Bearer {t}'}).status_code==200

def test_delete_asset_engineer_forbidden(client):
    t=token_for(client,'eng','pass'); aid=client.get('/api/assets').get_json()['data'][0]['_id']
    assert client.delete(f'/api/assets/{aid}',headers={'Authorization':f'Bearer {t}'}).status_code==403

def test_add_metric(client):
    t=token_for(client); aid=client.get('/api/assets').get_json()['data'][0]['_id']
    assert client.post(f'/api/assets/{aid}/metrics',headers={'Authorization':f'Bearer {t}'},json={'cpu_pct':50,'mem_pct':51,'disk_pct':49,'active_sessions':5}).status_code==201

def test_add_incident(client):
    t=token_for(client); aid=client.get('/api/assets').get_json()['data'][0]['_id']
    assert client.post(f'/api/assets/{aid}/incidents',headers={'Authorization':f'Bearer {t}'},json={'incident_id':'I1','title':'CPU','severity':'high','notes':'x'}).status_code==201

def test_update_incident(client):
    t=token_for(client); aid=client.get('/api/assets').get_json()['data'][0]['_id']
    client.post(f'/api/assets/{aid}/incidents',headers={'Authorization':f'Bearer {t}'},json={'incident_id':'I2','title':'CPU','severity':'high','notes':'x'})
    assert client.put(f'/api/assets/{aid}/incidents/I2',headers={'Authorization':f'Bearer {t}'},json={'resolved':True}).status_code==200

def test_filter_status(client):
    r=client.get('/api/assets?status=online').get_json()['data']
    assert all(x['status']=='online' for x in r)

def test_stats(client):
    assert client.get('/api/assets/stats').status_code==200
