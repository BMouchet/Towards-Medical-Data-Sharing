import base64
import time
from TLS_helper import TLSHelper
from nacl.signing import SigningKey
import inspect
import json
import nacl.hash, nacl.encoding
from display_helper import pretty_print
import copy
import re
import datetime

class TEE:
    def __init__(self, ca_cert_file, self_cert_file, key_file,  verifier_public_key):
        self.client_secure_connection = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.verifier_secure_connection = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.db_secure_connection = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.private_key = SigningKey.generate()
        self.public_key = self.private_key.verify_key
        self.verifier_public_key = verifier_public_key
        # self.access_token = None
        self.hasher = nacl.hash.sha256
        self.secret = "Secret"
        self.pipelines = {
            "get_height": [
                {"$match": {"avs": "$avs_param"}},
                {"$project": {"height": 1, "_id": 0}}
            ],

            "get_mean_height": [
                {"$group": {"_id": None, "mean_height": {"$avg": "$height"}}},
                {"$project": {"_id": 0}}
            ],

            "get_blood_pressure": [
                {"$match": {"avs": "$avs_param"}},
                {"$project": {"confidential_data.blood_pressure": 1, "_id": 0}}
            ],

            "get_mean_blood_pressure": [
                {"$group": {"_id": None, "mean_blood_pressure": {"$avg": "$confidential_data.blood_pressure"}}},
                {"$project": {"_id": 0}}
            ],

            "give_authorization": [
                {
                    "$set": {
                        "patient_id": "$patient_id_param",
                        "doctor_id": "$doctor_id_param",
                        "access_type": "$access_type_param",
                        "expiration": "$expiration_param"
                    }
                }
            ],

            "remove_authorization": [
                {"$match": {"patient_id": "$patient_id_param", "doctor_id": "$doctor_id_param"}},
                {"$delete": {}}
            ],
        }

    def get_public_key(self):
        return self.public_key
    
    def handle_client_request(self, client_host, client_port, verifier_host, verifier_port, db_host, db_port):
        self.client_secure_connection.connect(client_host, client_port)
        request = self.client_secure_connection.receive()
        query, params = json.loads(request)["query"], json.loads(request)["query_params"]
        pretty_print("TEE", f"Received request: {query} with params: {params}")
        
        try:
            pipeline = self.get_pipeline(query, params)
        except ValueError as e:
            pretty_print("TEE", f"Error: {e}")
            response = {"error": "Unavailable operation"}
            self.client_secure_connection.send(json.dumps(response).encode())
            return
        
        pretty_print("TEE", "Received request", request)
        request_hash = self.hasher(request.encode())
        pretty_print("TEE", "Requesting nonce")
        nonce = self.request_nonce(verifier_host, verifier_port, request_hash)
        pretty_print("TEE", "Received nonce", nonce)
        
        evidence = self.generate_evidence(request_hash, nonce)
        attestation = self.send_evidence(evidence, nonce)
        pretty_print("TEE", "Received attestation, ready to query db", attestation)
        
        # self.token = self.request_token(verifier_host, verifier_port, attestation)
        # signed_token = self.private_key.sign(self.token.encode())
        
        # Pass the pipeline to the Database class to query the database
        # db_response = self.query_db(db_host, db_port, pipeline, signed_token)
        db_response = self.query_db(db_host, db_port, pipeline, attestation, request)
        response = self.prepare_response(request, db_response, attestation)
        self.client_secure_connection.send(response.encode())


    def prepare_response(self, request, db_response, attestation):
        pretty_print("TEE", "Received response from database, signing it", db_response)
        signed_result = self.sign_result(db_response)
        signed_result = base64.b64encode(signed_result).decode('utf-8')
        attestation = json.loads(attestation)
        expiration = attestation["expiration"]
        attestation = attestation["attestation"]
        response = {"response": signed_result, "request": request, "attestation": attestation, "expiration": expiration}
        response = json.dumps(response)
        pretty_print("TEE", "Sending response", response)
        return response

    def request_nonce(self, verifier_host, verifier_port, request_hash):
        self.verifier_secure_connection.connect(verifier_host, verifier_port)
        request = {"request": "Request nonce", "params": base64.b64encode(request_hash).decode('utf-8')}
        self.verifier_secure_connection.send(json.dumps(request).encode())
        nonce = self.verifier_secure_connection.receive()
        return nonce
    
    def generate_evidence(self, request, nonce):
        source_bytes = inspect.getsource(TEE).encode('utf-8')  # Encode source code as bytes
        secret_bytes = self.secret.encode('utf-8')  # Encode secret as bytes
        nonce_json = json.loads(nonce)
        nonce_bytes = nonce_json["nonce"].encode('utf-8')  # Encode nonce as bytes

        # Concatenate all parts
        data_to_hash = source_bytes + secret_bytes + nonce_bytes

        # Hash the concatenated data
        source_hash = self.hasher(data_to_hash, encoder=nacl.encoding.HexEncoder)

        evidence = source_hash
        return self.private_key.sign(evidence) 
    
    def send_evidence(self, evidence, nonce):
        evidence_response = {"request": "Send evidence", "evidence": base64.b64encode(evidence).decode('utf-8'), "nonce": nonce}
        encoded_evidence = json.dumps(evidence_response).encode()
        
        pretty_print("TEE", "Generated evidence, sending it to Verifier", encoded_evidence)
        self.verifier_secure_connection.send(encoded_evidence) 
        attestation = self.verifier_secure_connection.receive()
        return attestation
    
    def request_token(self, verifier_host, verifier_port, attestation):
        # self.verifier_secure_connection.connect(verifier_host, verifier_port)
        request= {"request": "Request token", "attestation": attestation}
        self.verifier_secure_connection.send(json.dumps(request).encode())
        token = self.verifier_secure_connection.receive()

        return token
    
    def sign_request(self, request):
        return self.private_key.sign(request)
    
    def query_db(self, db_host, db_port, pipeline, attestation, request):
        self.db_secure_connection.connect(db_host, db_port)
        username = json.loads(request)["username"]
        password = json.loads(request)["password"]
        
        # Create the request with the pipeline and token
        # data = json.dumps({"pipeline": pipeline, "token": base64.b64encode(token).decode('utf-8')}).encode('utf-8')
        data = json.dumps({"pipeline": pipeline, "username": username, "password": password, "attestation": attestation}).encode('utf-8')

        pretty_print("TEE", "Querying database", data)
        self.db_secure_connection.send(data)

        # Receive the database response
        db_response = self.db_secure_connection.receive()
        return db_response
        
    def sign_result(self, db_response):
        signed_data = self.private_key.sign(db_response.encode('utf-8'))
        return signed_data
    
    def close_connections(self):
        try:
            self.client_secure_connection.close()
            self.verifier_secure_connection.close()
            self.db_secure_connection.close()
        except Exception as e:
            pretty_print("TEE", f"Error closing connections: {e}")
        
    def get_pipeline(self, pipeline_name, params):
        if pipeline_name not in self.pipelines:
            raise ValueError("Pipeline not found")

        # Deep copy the pipeline to avoid mutating the original
        pipeline = copy.deepcopy(self.pipelines[pipeline_name])

        # Validate and replace placeholders
        for stage in pipeline:
            for operator, fields in stage.items():
                if isinstance(fields, dict):  # Check for nested dictionaries
                    for field, value in fields.items():
                        if isinstance(value, str) and value.startswith("$"):
                            param_name = value[1:]  # Remove the '$' prefix
                            if param_name in params:
                                # Validate input here (e.g., check type, sanitize)
                                validated_value = self.validate_param(param_name, params[param_name])
                                fields[field] = validated_value
                            else:
                                raise ValueError(f"Missing parameter: {param_name}")
        return pipeline

    def validate_param(self, param_name, param_value):
        # Example: Add custom validation logic for each parameter
        if param_name == "avs_param":
            if not self.validate_avs_number(param_value):
                raise ValueError(f"Invalid value for {param_name}: {param_value}")
            return param_value
        elif param_name in ["patient_id_param", "doctor_id_param"]:
            if not self.validate_avs_number(param_value):
                raise ValueError(f"Invalid value for {param_name}: {param_value}")
            return param_value
        elif param_name == "access_type_param":
            if param_value not in ["read", "write"]:
                raise ValueError(f"Invalid access type: {param_value}")
            return param_value
        elif param_name == "expiration_param":
            if not isinstance(param_value, int) or param_value <= 0:
                raise ValueError(f"Invalid expiration time: {param_value}")
            return param_value
        else:
            raise ValueError(f"Unknown parameter: {param_name}")
        
    def validate_avs_number(self, avs_number):
        regex = r"^756\.\d{4}\.\d{4}\.\d{2}$"
        if re.match(regex, avs_number):
            return True
        else:
            return False
    
    def validate_expiration(self, param_name, param_value):
        if param_name == "expiration_param":
            if isinstance(param_value, str):
                try:
                    # Assuming the datetime format is "YYYY-MM-DD HH:MM:SS"
                    expiration_datetime = datetime.strptime(param_value, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    raise ValueError(f"Invalid expiration time format: {param_value}. Expected format is YYYY-MM-DD HH:MM:SS")
            elif isinstance(param_value, datetime):
                expiration_datetime = param_value
            else:
                raise ValueError(f"Invalid expiration time: {param_value}. It should be a datetime or a valid datetime string.")
            
            # Optionally, compare expiration to current time to check if it's in the future
            if expiration_datetime <= datetime.now():
                raise ValueError(f"Expiration time must be in the future: {param_value}")
            
            # Return the expiration datetime object
            return expiration_datetime
        
if __name__ == "__main__":
    tee = TEE(ca_cert_file="certs/ca-cert.pem", self_cert_file="certs/server-cert.pem", key_file="certs/server-key.pem", verifier_public_key=None)
    print(tee.pipelines["get_height"])
    print(tee.get_pipeline("get_height", {"avs_param": "756.1111.1111.11"}))