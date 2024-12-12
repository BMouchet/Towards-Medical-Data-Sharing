import json
import base64

def generate_request(keys, values):
    request_data = dict(zip(keys, values))
    request_json = json.dumps(request_data)
    return request_json

def prepare_bytes_for_json(data):
    return base64.b64encode(data).decode('utf-8')

def from_json_to_bytes(data):
    return data.encode('utf-8')