from bson import ObjectId
import re


def serialize_doc(doc):
    """Convert MongoDB ObjectId fields to strings recursively."""
    if isinstance(doc, list):
        return [serialize_doc(d) for d in doc]
    if isinstance(doc, dict):
        out = {}
        for k, v in doc.items():
            if isinstance(v, ObjectId):
                out[k] = str(v)
            elif isinstance(v, (dict, list)):
                out[k] = serialize_doc(v)
            else:
                out[k] = v
        return out
    return doc


def valid_ip(ip):
    """Validate basic IPv4 format and octet range."""
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip or ""):
        return False
    parts = [int(x) for x in ip.split(".")]
    return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
