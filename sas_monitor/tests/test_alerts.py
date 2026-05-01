from tests.conftest import token_for

def test_get_alerts(client):
    assert client.get('/api/alerts').status_code==200

def test_create_alert(client):
    t=token_for(client)
    r=client.post('/api/alerts',headers={'Authorization':f'Bearer {t}'},json={'asset_id':'a1','alert_type':'cpu_threshold','threshold_value':90,'actual_value':95,'severity':'critical'})
    assert r.status_code==201

def test_ack_alert(client):
    t=token_for(client); aid=client.get('/api/alerts').get_json()['data'][0]['_id']
    assert client.put(f'/api/alerts/{aid}/acknowledge',headers={'Authorization':f'Bearer {t}'}).status_code==200

def test_filter_alerts_by_severity(client):
    assert client.get('/api/alerts?severity=critical').status_code==200

def test_alert_summary(client):
    assert client.get('/api/alerts/summary').status_code==200
