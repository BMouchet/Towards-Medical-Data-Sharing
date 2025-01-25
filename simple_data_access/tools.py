import base64
import csv
import json


def generate_json_from_lists(keys: list, values: list) -> str:
    """Generates a JSON request from keys and values."""
    return json.dumps(dict(zip(keys, values)))

def prepare_bytes_for_json(data: bytes) -> str:
    """Encodes binary data for JSON transmission."""
    return base64.b64encode(data).decode('utf-8')

def from_json_to_bytes(data: str) -> bytes:
    """Converts a JSON string to bytes."""
    return data.encode('utf-8')

def write_data(file, data):
    """Writes binary data to a file."""
    with open(file, mode="a", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(data)