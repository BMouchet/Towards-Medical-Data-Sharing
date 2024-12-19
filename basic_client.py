from bson import ObjectId
from TLS_helper import TLSHelper
from display_helper import pretty_print
import json
import base64
import time
from nacl.signing import VerifyKey
from tools import generate_request, prepare_bytes_for_json

class BasicClient:
    def __init__(self, ca_cert_file, tee_public_key, verifier_public_key):
        self.connection_with_verifier = TLSHelper(ca_cert_file, is_server=False)
        self.connection_with_db_proxy = TLSHelper(ca_cert_file, is_server=False)
        self.tee_public_key = tee_public_key
        self.verifier_public_key = verifier_public_key
        pretty_print("CLIENT", "Initialized")
    
    def start(self, tee_host, tee_port, verifier_host, verifier_port):
        self.connection_with_verifier.connect(verifier_host, verifier_port)
        self.connection_with_db_proxy.connect(tee_host, tee_port)
        
        nonce = self.request_nonce()
        pretty_print("CLIENT", "Received nonce", nonce)
        
        evidence = self.request_evidence(nonce)
        pretty_print("CLIENT", "Received evidence", evidence)
        
        attestation = self.send_evidence(evidence)
        attestation = self.verify_attestation(attestation)
        query_result = None
        if attestation:
            query_result = self.send_query()
        else:
            self.stop()
            return
        query_result = self.verify_response(query_result)    
        pretty_print("CLIENT", "Request was successful", query_result)
        self.stop()
        return
            
        
    def request_nonce(self):
        pretty_print("CLIENT", "Requesting nonce")
        request = generate_request(["verb", "route"], ["GET", "nonce"])
        self.connection_with_verifier.send(request)
        nonce = self.connection_with_verifier.receive()
        return nonce
    
    def request_evidence(self, nonce):
        nonce = json.loads(nonce)['nonce']
        request = generate_request(["verb", "route", "nonce"], ["GET", "evidence", nonce])
        self.connection_with_db_proxy.send(request)
        evidence = self.connection_with_db_proxy.receive()
        return evidence
    
    def send_evidence(self, evidence):
        data = json.loads(evidence)
        evidence = data['evidence']
        nonce = data['nonce']
        request = generate_request(["verb", "route", "evidence", "nonce"], ["GET", "attestation", evidence, nonce])
        self.connection_with_verifier.send(request)
        attestation = self.connection_with_verifier.receive()
        return attestation
    
    def verify_attestation(self, attestation):
        attestation = json.loads(attestation)
        pretty_print("CLIENT", "Verifying attestation", attestation)
        attestation_signature = attestation['attestation']
        attestation_signature = base64.b64decode(attestation_signature)
        pretty_print("CLIENT", f"{attestation_signature}")
        attestation = self.verifier_public_key.verify(attestation_signature)
        pretty_print("CLIENT", "Attestation verified", attestation)
        attestation_json = json.loads(attestation)
        expiration = attestation_json['expiration']
        if(time.time() > expiration):
            pretty_print("CLIENT", "Attestation expired")
            return False
        else:
            pretty_print("CLIENT", "Attestation valid")
            return attestation
        
    def send_query(self):
        request = generate_request(["verb", "route", "username", "password", "params"], ["GET", "get_height", "doctor1", "password", {"patient_id": str(ObjectId('111111111111111111111111'))}])
        self.connection_with_db_proxy.send(request)
        response = self.connection_with_db_proxy.receive()
        return response
    
    def verify_response(self, response):
        try:
            response = json.loads(response)
            pretty_print("CLIENT", "Verifying response", response)
            response = response['response']
            response = base64.b64decode(response)
            response = self.tee_public_key.verify(response)
            return response
        except:
            return response
        
    def stop(self):
        response = generate_request(["close"], ["close"])
        self.connection_with_verifier.send(response)
        self.connection_with_db_proxy.send(response)
        try:
            self.connection_with_verifier.close()
            self.connection_with_db_proxy.close()    
        except:
            print("Connections already closed")
        finally:
            return
        
    