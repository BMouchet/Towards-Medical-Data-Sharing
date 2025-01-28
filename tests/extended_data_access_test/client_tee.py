import base64
import datetime
import inspect
import json
import os
import time

import dotenv
from TLS_helper import TLSHelper
from nacl.signing import SigningKey
from nacl.hash import sha256
from pymongo import MongoClient
from tools import generate_json_from_lists, prepare_bytes_for_json, from_json_to_bytes

class ClientTEE:
    # =============================================================================
    # Setup
    # =============================================================================
    def __init__(self, ca_cert_file, self_cert_file, key_file, db_proxy_public_key, verifier_public_key):
        self.connection_with_verifier = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.connection_with_db_proxy = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.connection_with_client = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.verifier_public_key = verifier_public_key
        self.db_tee_public_key = db_proxy_public_key
        self.private_signing_key = SigningKey.generate()
        self.public_signing_key = self.private_signing_key.verify_key
        self.listening = False
        self.loaded_pipeline = None
        self.methods = {"get_height": "get_height", "is_bp_above_mean": "get_bp"}
        client = MongoClient('localhost', 27017)
        db = client['test_dataset']
        self.bp = db['bps']
        self.pipelines = db['pipelines']
        self.nonce_freshness = None
        self.result_queue = None
        self.start_time = None
        
    def get_public_key(self):
        return self.public_signing_key
    
    def start(self, client_host, client_port, tee_host, tee_port, verifier_host, verifier_port, result_queue):
        self.result_queue = result_queue
        self.connection_with_client.connect(client_host, client_port)
        self.connection_with_verifier.connect(verifier_host, verifier_port)
        self.connection_with_db_proxy.connect(tee_host, tee_port)
        self.listening = True
        
        while self.listening:
            request = self.connection_with_client.receive()
            self.dispatch_request(request)
            
    def dispatch_request(self, request):
        request_json = json.loads(request)
        try:
            if request_json["method"] == "GET":
                if request_json["route"] in self.methods:
                    self.execute_query(request_json)
            else:
                self.stop()
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            self.stop()
            
    # =============================================================================
    # Query Execution
    # =============================================================================
            
    def execute_query(self, request_json):
        self.start_time = time.time()
        self.loaded_pipeline = self.pipelines.find_one({"name": request_json["route"]})
        query_name = self.methods[request_json["route"]]
        nonce = self.request_nonce()
        self.start_time = time.time()
        self.nonce_freshness = time.time()
        evidence_requested = self.request_evidence(nonce, query_name)
        self.start_time = time.time()
        attestation = self.send_evidence(evidence_requested, nonce, query_name)
        if not self.verify_attestation(attestation):
            print("Attestation verification failed")
            self.stop()
        duration = time.time() - self.start_time
        self.result_queue.put(("Attestation verification (Client)", duration))
        self.start_time = time.time()
        evidence_generated = self.generate_evidence(evidence_requested)
        response = self.send_query(request_json, evidence_generated, evidence_requested)
        self.start_time = time.time()
        response = self.verify_response(response)
        if not response:
            print("Response verification failed")
            self.stop()
        duration = time.time() - self.start_time
        self.result_queue.put(("Response verification (Client)", duration))
        response = self.process_response(response)
        start_time = time.time()    
        response = self.sign_response(response)
        duration = time.time() - start_time
        self.result_queue.put(("Response signing (Client)", duration))
        self.send_response(response)
        self.stop()
        
    # =============================================================================
    # Nonce request
    # =============================================================================
        
    def request_nonce(self):
        request = generate_json_from_lists(["method", "route"], ["GET", "nonce"])
        duration = time.time() - self.start_time
        self.result_queue.put(("Nonce request client", duration))
        self.connection_with_verifier.send(request)
        return self.connection_with_verifier.receive()
    
    # =============================================================================
    # Requesting and sending evidence
    # =============================================================================
    
    def request_evidence(self, nonce, query_name):
        nonce = json.loads(nonce)["nonce"]
        request = generate_json_from_lists(["method", "route", "nonce", "query_name"], ["GET", "evidence", nonce, query_name])
        duration = time.time() - self.start_time
        self.result_queue.put(("Evidence request client", duration))
        self.connection_with_db_proxy.send(request)
        return self.connection_with_db_proxy.receive()

    def send_evidence(self, evidence, nonce, query_name):
        evidence = json.loads(evidence)
        source_code_claim = evidence["source_code_claim"]
        loaded_pipeline_claim = evidence["loaded_pipeline_claim"]
        nonce = evidence["received_nonce"]

        request = generate_json_from_lists(["method", "route", "source_code_claim", "loaded_pipeline_claim", "nonce", "query_name"], ["GET", "attestation", source_code_claim, loaded_pipeline_claim, nonce, query_name])
        duration = time.time() - self.start_time
        self.result_queue.put(("Evidence sent to Verifier by client", duration))
        self.connection_with_verifier.send(request)
        return self.connection_with_verifier.receive()
    
    # =============================================================================
    # Attestation verification
    # =============================================================================
    
    def verify_attestation(self, attestation):
        try:
            attestation = json.loads(attestation)
            attestation_signature = attestation['attestation']
            attestation_signature = base64.b64decode(attestation_signature)
            attestation = self.verifier_public_key.verify(attestation_signature)
            expiration = json.loads(attestation)["expiration"]
            if time.time() > expiration:
                return False
            if time.time() - self.nonce_freshness > 300:
                return False
            return True
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            
    # =============================================================================
    # Evidence self generation
    # =============================================================================
    
    def generate_evidence(self, evidence_requested):
        nonce = json.loads(evidence_requested)["requested_nonce"]
        nonce = json.loads(nonce)["nonce"]
        source_code = inspect.getsource(ClientTEE)
        source_code_hash = sha256(source_code.encode() + from_json_to_bytes(nonce))
        signed_source_code_claim = self.private_signing_key.sign(source_code_hash)
        loaded_pipeline_hash = sha256(str(self.loaded_pipeline["pipeline"]).encode() + from_json_to_bytes(nonce))

        signed_loaded_pipeline_claim = self.private_signing_key.sign(loaded_pipeline_hash)
        
        return signed_source_code_claim, signed_loaded_pipeline_claim
    
    # =============================================================================
    # Sending query and evidence
    # =============================================================================
        
    def send_query(self, query, evidence_generated, evidence_requested):
        query["source_code_claim"] = prepare_bytes_for_json(evidence_generated[0])
        query["loaded_pipeline_claim"] = prepare_bytes_for_json(evidence_generated[1])
        nonce = json.loads(evidence_requested)["requested_nonce"]
        query["nonce"] = json.loads(nonce)["nonce"]
        query["route"] = self.methods[query["route"]]
        query["loaded_pipeline"] = self.loaded_pipeline["name"]
        query = json.dumps(query)
        duration = time.time() - self.start_time
        self.result_queue.put(("Evidence generation (Client)", duration))
        self.connection_with_db_proxy.send(query)
        return self.connection_with_db_proxy.receive()
    
    # =============================================================================
    # Response verification and processing
    # =============================================================================
    
    def verify_response(self, response):   
        try:
            response = json.loads(response)
            decoded_response = base64.b64decode(response["result"])
            verified_response = self.db_tee_public_key.verify(decoded_response)
            return verified_response
        except Exception as e:
            return str(e)
    
    def process_response(self, response):
        data = response.decode('utf-8')
        data = json.loads(data)
        data = data[0]['bp']
        start_time = time.time()
        pipeline = self.build_pipeline({"input_bp": data})
        duration = time.time() - start_time
        self.result_queue.put(("Pipeline building (Client)", duration))
        start_time = time.time()
        response = list(self.bp.aggregate(pipeline))
        duration = time.time() - start_time
        self.result_queue.put(("Pipeline execution (Client)", duration))
        return response
    
    def sign_response(self, response):
        response = json.dumps(response)
        response = response.encode()
        signed_response = self.private_signing_key.sign(response)
        return signed_response
    
    def send_response(self, response):
        response = generate_json_from_lists(["result"], [prepare_bytes_for_json(response)])
        self.connection_with_client.send(response)
    
    
    # =============================================================================
    # Pipeline building and parameter validation
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
        self.loaded_pipeline = self.loaded_pipeline["pipeline"]
        return replace_placeholders(self.loaded_pipeline)

    
    def validate_param(self, param_name, param_value):
        if param_name in ["input_bp"]:
            if not isinstance(param_value, (int, float)):
                raise ValueError(f"Invalid parameter value for {param_name}: {param_value}")
            return param_value
        else:
            raise ValueError(f"Invalid parameter name: {param_name}")
        

    def stop(self):
        self.listening = False
        try:
            close_request = generate_json_from_lists(["close"], ["close"])
            self.connection_with_verifier.send(close_request)
            self.connection_with_db_proxy.send(close_request)
            self.connection_with_client.send(close_request)
            self.connection_with_verifier.close()
            self.connection_with_db_proxy.close()
            self.connection_with_client.close()
        except:
            pass