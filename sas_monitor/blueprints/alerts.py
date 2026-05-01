"""Alerts endpoints for CRUD, acknowledge and aggregation summary."""
from datetime import datetime
from bson import ObjectId
from bson.errors import InvalidId
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from config import ALLOWED_ALERT_TYPES, ALLOWED_SEVERITY, db
from blueprints.helpers import serialize_doc

alerts_bp=Blueprint('alerts',__name__)
alerts=db['alerts']

def _admin_only():
    return (get_jwt_identity() or {}).get('role')=='admin'

@alerts_bp.route('',methods=['GET'])
def list_alerts():
    """List alerts with filters including date range."""
    q={}
    for k in ['severity','asset_id']:
        if request.args.get(k): q[k]=request.args.get(k)
    if request.args.get('acknowledged') is not None:
        q['acknowledged']=request.args.get('acknowledged').lower()=='true'
    if request.args.get('from') or request.args.get('to'):
        q['triggered_at']={}
        if request.args.get('from'): q['triggered_at']['$gte']=datetime.fromisoformat(request.args.get('from'))
        if request.args.get('to'): q['triggered_at']['$lte']=datetime.fromisoformat(request.args.get('to'))
    return jsonify({'data':serialize_doc(list(alerts.find(q)))}),200

@alerts_bp.route('/<alert_id>',methods=['GET'])
def get_alert(alert_id):
    """Get single alert by id."""
    try: oid=ObjectId(alert_id)
    except InvalidId:return jsonify({'error':'Invalid ID format'}),400
    d=alerts.find_one({'_id':oid})
    if not d:return jsonify({'error':'Alert not found'}),404
    return jsonify({'data':serialize_doc(d)}),200

@alerts_bp.route('',methods=['POST'])
@jwt_required()
def create_alert():
    """Create a new alert document."""
    d=request.get_json() or {}
    req=['asset_id','alert_type','threshold_value','actual_value','severity']
    m=[f for f in req if d.get(f) is None]
    if m:return jsonify({'error':f"Missing fields: {', '.join(m)}"}),400
    if d['severity'] not in ALLOWED_SEVERITY:return jsonify({'error':'Invalid severity'}),400
    if d['alert_type'] not in ALLOWED_ALERT_TYPES:return jsonify({'error':'Invalid alert_type'}),400
    d.update({'triggered_at':datetime.utcnow(),'acknowledged':False,'acknowledged_by':None})
    r=alerts.insert_one(d)
    return jsonify({'message':'Alert created','data':{'id':str(r.inserted_id)}}),201

@alerts_bp.route('/<alert_id>/acknowledge',methods=['PUT'])
@jwt_required()
def ack(alert_id):
    """Acknowledge alert and set user."""
    try:oid=ObjectId(alert_id)
    except InvalidId:return jsonify({'error':'Invalid ID format'}),400
    ident=get_jwt_identity() or {}
    r=alerts.update_one({'_id':oid},{'$set':{'acknowledged':True,'acknowledged_by':ident.get('username')}})
    if r.matched_count==0:return jsonify({'error':'Alert not found'}),404
    return jsonify({'message':'Alert acknowledged'}),200

@alerts_bp.route('/<alert_id>',methods=['DELETE'])
@jwt_required()
def delete_alert(alert_id):
    """Delete alert by id (admin only)."""
    if not _admin_only():return jsonify({'error':'Forbidden'}),403
    try:oid=ObjectId(alert_id)
    except InvalidId:return jsonify({'error':'Invalid ID format'}),400
    r=alerts.delete_one({'_id':oid})
    if r.deleted_count==0:return jsonify({'error':'Alert not found'}),404
    return jsonify({'message':'Alert deleted'}),200

@alerts_bp.route('/summary',methods=['GET'])
def summary():
    """Return grouped alert counts by severity and type using facet."""
    p=[{'$facet':{'by_severity':[{'$group':{'_id':'$severity','count':{'$sum':1}}}], 'by_alert_type':[{'$group':{'_id':'$alert_type','count':{'$sum':1}}}]}}]
    return jsonify({'data':serialize_doc(list(alerts.aggregate(p))[0])}),200
