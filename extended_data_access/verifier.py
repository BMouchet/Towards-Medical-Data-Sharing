import base64
import json
import time
from TLS_helper import TLSHelper
import inspect
from tee_db_proxy import TEE_DB_Proxy
from nacl.signing import SigningKey
import nacl.utils, nacl.secret
from tools import generate_json_from_lists, prepare_bytes_for_json, from_json_to_bytes
from nacl.hash import sha256
import threading
from pymongo import MongoClient
from client_tee import ClientTEE

class Verifier:
    # =============================================================================
    # Setup
    # =============================================================================
    def __init__(self, ca_cert_file, self_cert_file, key_file):
        self.connections = {}
        self.test = None
        self.connections["Client"] = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.connections["TEE"] = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.db_proxy_source_code = inspect.getsource(TEE_DB_Proxy)
        self.client_tee_source_code = inspect.getsource(ClientTEE)
        self.tee_public_key = None
        self.client_tee_public_key = None
        self.pending_verifications = {}
        self.expiration = 300
        self.private_signing_key = SigningKey.generate()
        self.public_signing_key = self.private_signing_key.verify_key
        self.listening = False
        self.threads = {}
        client = MongoClient('localhost', 27017)
        db = client['pipelines']
        self.approved_pipelines = db['approved_pipelines']
        
    def set_tee_public_key(self, tee_public_key):
        self.tee_public_key = tee_public_key
    
    def set_client_tee_public_key(self, client_tee_public_key):
        self.client_tee_public_key = client_tee_public_key
    
    def get_public_key(self):
        return self.public_signing_key
    
    def handle_connection(self, connection):
        while self.listening:
            try:
                request = self.connections[connection].receive()
                self.dispatch_request(request, connection)
            except:
                self.stop()
                
    def start(self, host, port, other_port):
        self.listening = True
        self.connections["Client"].connect(host, port)
        self.threads["Client"] = threading.Thread(target=self.handle_connection, args=("Client",))
        self.threads["Client"].start()
        self.connections["TEE"].connect(host, other_port)
        self.threads["TEE"] = threading.Thread(target=self.handle_connection, args=("TEE",))
        self.threads["TEE"].start()
        
    def dispatch_request(self, request, connection):    
        request_json = json.loads(request)
        try:
            if request_json["method"] == "GET":
                if request_json["route"] == "nonce":
                    self.nonce_requested(connection)
                if request_json["route"] == "attestation":
                    self.attestation_requested(request_json, connection)
            else:
                self.stop()
        except Exception as e:
            self.connections[connection].send(json.dumps({"error": str(e)}))
            self.stop()
    
    def stop(self):
        try:
            for connection in self.connections:
                self.connections[connection].close()
            self.listening = False
        except Exception:
            pass
        
    # =============================================================================
    # Nonce Request
    # =============================================================================
    def nonce_requested(self, connection):
        nonce = self.generate_nonce()
        self.send_nonce(nonce, connection)
    
    def generate_nonce(self):
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        self.test = nonce
        self.pending_verifications[prepare_bytes_for_json(nonce)] = time.time()
        return nonce
    
    def send_nonce(self, nonce, connection):
        try:
            response = generate_json_from_lists(["nonce"], [prepare_bytes_for_json(nonce)])
            self.connections[connection].send(response)
        except Exception as e:
            print(e)
        
    # =============================================================================
    # Attestation Request / Evidence Verification
    # =============================================================================
    def attestation_requested(self, request_json, connection):
        attestation = self.verify_evidence(request_json, connection)
        self.send_attestation(attestation, connection)
        
    def verify_evidence(self, request_json, connection):
        source_code_claim = request_json["source_code_claim"]
        loaded_pipeline_claim = request_json["loaded_pipeline_claim"]
        query_name = request_json["query_name"]
        nonce = request_json["nonce"]
        if nonce not in self.pending_verifications:
            return False
        
        if time.time() - self.pending_verifications[nonce] > self.expiration:
            return False
        received_source_code_claim = self.verify_claim(source_code_claim, connection)
        received_loaded_pipeline_claim = self.verify_claim(loaded_pipeline_claim, connection)
        
        known_source_code_claim = self.compute_known_source_code_claim(nonce, connection)
        known_pipeline_claim = self.compute_known_pipeline_claim(nonce, query_name)
        if received_source_code_claim == known_source_code_claim and received_loaded_pipeline_claim == known_pipeline_claim:
            expiration = time.time() + self.expiration
            evidence = {"expiration": expiration, "source_code_claim": source_code_claim, "loaded_pipeline_claim": loaded_pipeline_claim}
            evidence_json = json.dumps(evidence, separators=(',', ':')).encode('utf-8') 
            attestation = self.private_signing_key.sign(evidence_json)
            return attestation
        return False

    def verify_claim(self, claim, connection): 
        bytes_claim = base64.b64decode(claim)
        if connection == "TEE":
            return self.client_tee_public_key.verify(bytes_claim)
        else:
            return self.tee_public_key.verify(bytes_claim)
    
    def compute_known_source_code_claim(self, nonce, connection):
        if connection in self.connections:
            if connection == "Client":
                return sha256(self.db_proxy_source_code.encode() + from_json_to_bytes(nonce))
            else:
                return sha256(self.client_tee_source_code.encode() + from_json_to_bytes(nonce))
        return False

    def compute_known_pipeline_claim(self, nonce, query_name):
        try:
            pipeline = self.approved_pipelines.find_one({"name": query_name})["pipeline"]
            hash = sha256(str(pipeline).encode() + from_json_to_bytes(nonce))
            return hash
        except Exception as e:
            return False
    
    def send_attestation(self, attestation, connection):
        response = generate_json_from_lists(["attestation"], [prepare_bytes_for_json(attestation)])
        self.connections[connection].send(response)
        
    