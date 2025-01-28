import datetime
import inspect
import json
import logging
import time
from bson import ObjectId
from TLS_helper import TLSHelper
from tools import generate_json_from_lists, from_json_to_bytes, prepare_bytes_for_json
from nacl.signing import SigningKey
from nacl.hash import sha256
from pymongo import MongoClient
import os
import dotenv

class TEE_DB_Proxy:
    # =============================================================================
    # Setup
    # =============================================================================
    def __init__(self, ca_cert_file, self_cert_file, key_file):
        self.connection_with_client = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.listening = False
        self.private_signing_key = SigningKey.generate()
        self.public_signing_key = self.private_signing_key.verify_key
        self.routes = {
            "get_height",
            "get_bp"
        }
        dotenv.load_dotenv()
        username = os.getenv('TEE_DB_USERNAME')
        password = os.getenv('TEE_DB_PASSWORD')
        self.uri = f'mongodb://{username}:{password}@localhost:27017/'
        self.loaded_pipeline = None
        self.client = MongoClient(self.uri)
        self.db = self.client['test_dataset']
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(filename='tee_db_proxy.log', level=logging.INFO)
        self.result_queue = None

    
    def get_public_key(self):
        return self.public_signing_key
    
    def start(self, host, port, result_queue):
        self.result_queue = result_queue
        self.connection_with_client.connect(host, port)
        self.listening = True
        while self.listening:
            request = self.connection_with_client.receive()
            self.dispatch_request(request) 
            
    def dispatch_request(self, request):
        try:
            request_json = json.loads(request)
            if request_json["method"] == "GET":
                if request_json["route"] == 'evidence':
                    self.evidence_requested(request_json)
                if request_json["route"] in self.routes:
                    self.query_execution_requested(request_json)
            else:
                self.stop()
        except Exception as e:
            self.connection_with_client.send(json.dumps({"error": str(e)}))
            self.stop()
            
    def stop(self):
        self.listening = False
        try:
            self.connection_with_client.close()
        except Exception:
            pass
                  
    # =============================================================================
    # Evidence Generation
    # =============================================================================
                    
    def evidence_requested(self, request_json):
        start_time = time.time()
        nonce = request_json["nonce"]
        query_name = request_json["query_name"]
        evidence = self.generate_evidence(nonce, query_name)
        self.send_evidence(evidence, nonce)
        duration = time.time() - start_time
        self.result_queue.put(("Evidence generation (Proxy)", duration))
    
    def generate_evidence(self, nonce, query_name):
        source_code = inspect.getsource(TEE_DB_Proxy)
        source_code_hash = sha256(source_code.encode() + from_json_to_bytes(nonce))
        signed_source_code_claim = self.private_signing_key.sign(source_code_hash)
        
        self.loaded_pipeline = self.db['pipelines'].find_one({"name": query_name})["pipeline"]
        loaded_pipeline_hash = sha256(str(self.loaded_pipeline).encode() + from_json_to_bytes(nonce))
        signed_loaded_pipeline_claim = self.private_signing_key.sign(loaded_pipeline_hash)
        
        return signed_source_code_claim, signed_loaded_pipeline_claim
        
    def send_evidence(self, evidence, nonce):
        response = generate_json_from_lists(["source_code_claim", "loaded_pipeline_claim", "nonce"], [prepare_bytes_for_json(evidence[0]), prepare_bytes_for_json(evidence[1]), nonce])
        self.connection_with_client.send(response)
        
    # =============================================================================
    # Query Execution
    # =============================================================================
    
    def query_execution_requested(self, request_json):
        request_json['params']["attestation"] = False
        response = self.execute_query(request_json)
        start_time = time.time()    
        signed_result = self.sign_result(response)
        duration = time.time() - start_time
        self.result_queue.put(("Siging Result (Proxy)", duration))
        self.send_result(signed_result)
            
    def execute_query(self, request_json):
        start_time = time.time()
        user = self.authenticate_user(request_json['username'], request_json['password'])
        duration = time.time() - start_time
        self.result_queue.put(("Authentication", duration))
        start_time = time.time()
        request_json['params']['user_id'] = user['_id']
        self.loaded_pipeline = self.build_pipeline(request_json['params'])
        duration = time.time() - start_time
        self.result_queue.put(("Building Pipeline", duration))
        start_time = time.time()
        result = list(self.db.patients.aggregate(self.loaded_pipeline))
        duration = time.time() - start_time
        self.result_queue.put(("Pipeline Execution", duration))
        # Record track simulation
        self.logger.info(
            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}: User {user['_id']} executed query {request_json['route']} with parameters {request_json['params']}"
        )
        return result
    
    def sign_result(self, result):
        result = json.dumps(result)
        result = result.encode()
        signed_result = self.private_signing_key.sign(result)
        return signed_result
        
    def send_result(self, signed_result):
        response = generate_json_from_lists(["result"], [prepare_bytes_for_json(signed_result)])
        self.connection_with_client.send(response)
        
    def authenticate_user(self, username, password):
        """
        This method is more meant to find the user id than being a realistic authentication method.
        """
        user = self.db['users'].find_one({"username": username, "password": password})
        if user is None:
            raise Exception("Invalid username or password")
        return user
    
    # =============================================================================
    # Pipeline Building Tools
    # =============================================================================
    
    def build_pipeline(self, params):
        for param_name, param_value in params.items():
            params[param_name] = self.validate_param(param_name, param_value)

        
        def replace_placeholders(obj):
                if isinstance(obj, dict):
                    # Recursively process dictionaries
                    return {key: replace_placeholders(value) for key, value in obj.items()}
                elif isinstance(obj, list):
                    # Recursively process lists
                    return [replace_placeholders(item) for item in obj]
                elif isinstance(obj, str) and obj.startswith("$"):
                    # Replace placeholders that match keys in params
                    placeholder = obj[1:]  # Remove leading $
                    validated_value = params.get(placeholder, obj)
                    return validated_value  # Replace if key exists in params
                return obj

        return replace_placeholders(self.loaded_pipeline)
    
    def validate_param(self, param_name, param_value):
        if param_name in ["patient_id", "user_id", "access_control_id", "target_user_id"]:
            if not isinstance(param_value, ObjectId):
                try:
                    param_value = ObjectId(param_value)
                except Exception as e:
                    raise ValueError(f"Invalid value for {param_name}: {param_value}. Error: {e}")
            return param_value
        elif param_name in ["access_control_path"]:
            if not isinstance(param_value, str):
                raise ValueError(f"Invalid value for {param_name}: {param_value}")
            return param_value
        elif param_name == "height_input":
            if not isinstance(param_value, (int, float)):
                raise ValueError(f"Invalid height input: {param_value}")
            return param_value
        elif param_name == "attestation":
            if not isinstance(param_value, bool):
                raise ValueError(f"Invalid attestation value: {param_value}")
            return param_value
        else:
            raise ValueError(f"Invalid parameter name: {param_name}")
        