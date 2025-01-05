import base64
import json


def generate_request(keys: list, values: list) -> str:
    """Generates a JSON request from keys and values."""
    return json.dumps(dict(zip(keys, values)))

def prepare_bytes_for_json(data: bytes) -> str:
    """Encodes binary data for JSON transmission."""
    return base64.b64encode(data).decode('utf-8')

def from_json_to_bytes(data: str) -> bytes:
    """Converts a JSON string to bytes."""
    return data.encode('utf-8')