"""Assets endpoints for CRUD, metrics, incidents, search and stats."""
from datetime import datetime
from bson import ObjectId
from bson.errors import InvalidId
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from config import ALLOWED_ENVIRONMENTS, ALLOWED_SEVERITY, ALLOWED_STATUS, db
from blueprints.helpers import serialize_doc, valid_ip

assets_bp = Blueprint("assets", __name__)
assets = db["assets"]

def _admin_only():
    ident = get_jwt_identity() or {}
    return ident.get("role") == "admin"

@assets_bp.route("", methods=["GET"])
def list_assets():
    """List assets with filter and pagination."""
    q = {}
    for key in ["status", "environment", "region"]:
        if request.args.get(key): q[key]=request.args[key]
    page = int(request.args.get("page",1)); per_page=int(request.args.get("per_page",10))
    docs = list(assets.find(q).skip((page-1)*per_page).limit(per_page))
    return jsonify({"data": serialize_doc(docs)}), 200

@assets_bp.route("/<asset_id>", methods=["GET"])
def get_asset(asset_id):
    """Get single asset by id."""
    try: oid = ObjectId(asset_id)
    except InvalidId: return jsonify({"error":"Invalid ID format"}),400
    doc=assets.find_one({"_id":oid})
    if not doc: return jsonify({"error":"Asset not found"}),404
    return jsonify({"data": serialize_doc(doc)}),200

@assets_bp.route("", methods=["POST"])
@jwt_required()
def create_asset():
    """Create new asset record."""
    data=request.get_json() or {}
    req=["name","environment","region","os","sas_version","ip_address","status"]
    missing=[f for f in req if not data.get(f)]
    if missing: return jsonify({"error":f"Missing fields: {', '.join(missing)}"}),400
    if data["status"] not in ALLOWED_STATUS: return jsonify({"error":"Invalid status"}),400
    if data["environment"] not in ALLOWED_ENVIRONMENTS: return jsonify({"error":"Invalid environment"}),400
    if not valid_ip(data["ip_address"]): return jsonify({"error":"Invalid ip_address"}),400
    ident=get_jwt_identity() or {}
    data.update({"added_by":ident.get("username","unknown"),"added_on":datetime.utcnow(),"tags":data.get("tags",[]),"metrics":[],"incidents":[]})
    res=assets.insert_one(data)
    return jsonify({"message":"Asset created","data":{"id":str(res.inserted_id)}}),201

@assets_bp.route("/<asset_id>", methods=["PUT"])
@jwt_required()
def update_asset(asset_id):
    """Update top-level asset fields."""
    try: oid=ObjectId(asset_id)
    except InvalidId: return jsonify({"error":"Invalid ID format"}),400
    upd=request.get_json() or {}
    if "status" in upd and upd["status"] not in ALLOWED_STATUS: return jsonify({"error":"Invalid status"}),400
    r=assets.update_one({"_id":oid},{"$set":upd})
    if r.matched_count==0: return jsonify({"error":"Asset not found"}),404
    return jsonify({"message":"Asset updated"}),200

@assets_bp.route('/<asset_id>', methods=['DELETE'])
@jwt_required()
def delete_asset(asset_id):
    """Delete asset (admin only)."""
    if not _admin_only(): return jsonify({"error":"Forbidden"}),403
    try: oid=ObjectId(asset_id)
    except InvalidId: return jsonify({"error":"Invalid ID format"}),400
    r=assets.delete_one({"_id":oid})
    if r.deleted_count==0: return jsonify({"error":"Asset not found"}),404
    return jsonify({"message":"Asset deleted"}),200

@assets_bp.route('/search', methods=['GET'])
def search_assets():
    """Multi-field regex search on assets."""
    cond=[]
    for f in ["name","region","environment","status"]:
        v=request.args.get(f)
        if v: cond.append({f:{"$regex":v,"$options":"i"}})
    q={"$and":cond} if cond else {}
    return jsonify({"data":serialize_doc(list(assets.find(q)))}),200

@assets_bp.route('/stats', methods=['GET'])
def stats_assets():
    """Aggregate average metrics by environment and count by status."""
    pipeline=[{"$facet":{
        "environment_metrics":[{"$unwind":"$metrics"},{"$group":{"_id":"$environment","avg_cpu":{"$avg":"$metrics.cpu_pct"},"avg_mem":{"$avg":"$metrics.mem_pct"},"avg_disk":{"$avg":"$metrics.disk_pct"}}}],
        "status_counts":[{"$group":{"_id":"$status","count":{"$sum":1}}}]
    }}]
    return jsonify({"data":serialize_doc(list(assets.aggregate(pipeline))[0])}),200

@assets_bp.route('/<asset_id>/metrics', methods=['POST'])
@jwt_required()
def add_metric(asset_id):
    """Add metric subdocument to asset."""
    try: oid=ObjectId(asset_id)
    except InvalidId: return jsonify({"error":"Invalid ID format"}),400
    d=request.get_json() or {}
    for f in ["cpu_pct","mem_pct","disk_pct","active_sessions"]:
        if f not in d: return jsonify({"error":f"Missing fields: {f}"}),400
    if any(not (0 <= float(d[k]) <= 100) for k in ["cpu_pct","mem_pct","disk_pct"]): return jsonify({"error":"Metric percentages must be 0-100"}),400
    if int(d["active_sessions"])<0: return jsonify({"error":"active_sessions must be non-negative"}),400
    metric={"recorded_at":datetime.utcnow(),"cpu_pct":float(d["cpu_pct"]),"mem_pct":float(d["mem_pct"]),"disk_pct":float(d["disk_pct"]),"active_sessions":int(d["active_sessions"])}
    r=assets.update_one({"_id":oid},{"$push":{"metrics":metric}})
    if r.matched_count==0: return jsonify({"error":"Asset not found"}),404
    return jsonify({"message":"Metric added"}),201

@assets_bp.route('/<asset_id>/incidents', methods=['POST'])
@jwt_required()
def add_incident(asset_id):
    """Add incident subdocument."""
    try: oid=ObjectId(asset_id)
    except InvalidId: return jsonify({"error":"Invalid ID format"}),400
    d=request.get_json() or {}
    for f in ["incident_id","title","severity","notes"]:
        if not d.get(f): return jsonify({"error":f"Missing fields: {f}"}),400
    if d["severity"] not in ALLOWED_SEVERITY: return jsonify({"error":"Invalid severity"}),400
    ident=get_jwt_identity() or {}
    inc={"incident_id":d["incident_id"],"title":d["title"],"severity":d["severity"],"reported_by":ident.get("username"),"reported_at":datetime.utcnow(),"resolved":False,"notes":d["notes"]}
    r=assets.update_one({"_id":oid},{"$push":{"incidents":inc}})
    if r.matched_count==0: return jsonify({"error":"Asset not found"}),404
    return jsonify({"message":"Incident added"}),201

@assets_bp.route('/<asset_id>/incidents/<incident_id>', methods=['PUT'])
@jwt_required()
def update_incident(asset_id, incident_id):
    """Update incident subdocument by incident id."""
    try: oid=ObjectId(asset_id)
    except InvalidId: return jsonify({"error":"Invalid ID format"}),400
    d=request.get_json() or {}
    set_fields={f"incidents.$[elem].{k}":v for k,v in d.items()}
    r=assets.update_one({"_id":oid},{"$set":set_fields},array_filters=[{"elem.incident_id":incident_id}])
    if r.matched_count==0:return jsonify({"error":"Asset not found"}),404
    return jsonify({"message":"Incident updated"}),200

@assets_bp.route('/<asset_id>/metrics', methods=['GET'])
def get_metrics(asset_id):
    """Get all metric snapshots for asset."""
    try: oid=ObjectId(asset_id)
    except InvalidId: return jsonify({"error":"Invalid ID format"}),400
    doc=assets.find_one({"_id":oid},{"metrics":1})
    if not doc:return jsonify({"error":"Asset not found"}),404
    return jsonify({"data":serialize_doc(doc.get('metrics',[]))}),200

@assets_bp.route('/<asset_id>/incidents/<incident_id>', methods=['DELETE'])
@jwt_required()
def delete_incident(asset_id, incident_id):
    """Delete incident subdocument by incident id."""
    try: oid=ObjectId(asset_id)
    except InvalidId: return jsonify({"error":"Invalid ID format"}),400
    r=assets.update_one({"_id":oid},{"$pull":{"incidents":{"incident_id":incident_id}}})
    if r.matched_count==0:return jsonify({"error":"Asset not found"}),404
    return jsonify({"message":"Incident deleted"}),200
