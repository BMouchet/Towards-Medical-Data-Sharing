import base64
import inspect
import json
import time
from TLS_helper import TLSHelper
from display_helper import pretty_print
from nacl.signing import SigningKey
from nacl.hash import sha256

from tools import from_json_to_bytes, generate_request, prepare_bytes_for_json

class ClientTEE:
    def __init__(self, ca_cert_file, self_cert_file, key_file, db_tee_public_key, verifier_public_key):
        self.connection_with_verifier = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.connection_with_db_proxy = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.connection_with_client = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.verifier_public_key = verifier_public_key
        self.db_tee_public_key = db_tee_public_key
        self.private_signing_key = SigningKey.generate()
        self.public_signing_key = self.private_signing_key.verify_key
        self.listening = False
        self.methods = {"get_height": True, "is_heavier_than": True}
        self.loaded_pipeline = "AAA"
        pretty_print("CLIENT TEE", "Initialized")
        
    def get_public_key(self):   
        return self.public_signing_key
        
    def start(self, client_host, client_port, tee_host, tee_port, verifier_host, verifier_port):
        self.connection_with_client.connect(client_host, client_port)
        self.connection_with_verifier.connect(verifier_host, verifier_port)
        self.connection_with_db_proxy.connect(tee_host, tee_port)
        self.listening = True
        
        while self.listening:
            request = self.connection_with_client.receive()
            self.dispatch_request(request)
        
    def dispatch_request(self, request):
        request_json = json.loads(request)  
        pretty_print("CLIENT TEE", "Received request", request_json)
        try:
            if request_json['verb'] == 'GET' and request_json['route'] in self.methods:
                self.execute_query(request_json)
        except:
            if 'error' in request_json or 'close' in request_json:
                pretty_print("Client TEE", "Received close request")
                self.listening = False
                self.stop()
                
    def execute_query(self, query):
        self.start_attestation_protocol(query)
        response = generate_request(["response"], ["response"])
        return response
    
    def start_attestation_protocol(self, query):
        nonce = self.request_nonce()
        pretty_print("CLIENT TEE", "Received nonce", nonce)
        evidence_requested = self.request_evidence(nonce)
        pretty_print("CLIENT TEE", "Received evidence", evidence_requested)
        attestation = self.send_evidence_to_verifier(evidence_requested)
        pretty_print("CLIENT TEE", "Received attestation", attestation)
        attestation = self.verify_attestation(attestation)
        if not attestation:
            pretty_print("CLIENT TEE", "Attestation failed")
            self.stop()
            return
        pretty_print("CLIENT TEE", "Attestation succeeded, sending query")
        response = self.send_query(query)
        pretty_print("CLIENT TEE", f"Is contained ? {'evidence' in response}")
        response_json = json.loads(response)
        if response_json['verb'] == 'GET' and response_json['route'] == 'evidence':
            pretty_print("CLIENT TEE", "Attestation requested", response)
            nonce = response_json['nonce']
            evidence_requested, pipeline_evidence = self.generate_evidence(nonce)
            evidence_requested = prepare_bytes_for_json(evidence_requested)
            pipeline_evidence = prepare_bytes_for_json(pipeline_evidence)
            pretty_print("CLIENT TEE", "Evidence generated")
            response = self.send_evidence_to_db_proxy(evidence_requested, pipeline_evidence, nonce, query)
        pretty_print("CLIENT TEE", "Response received")
        response = self.verify_response(response)
        pretty_print("CLIENT TEE", "Response verified")
        response = self.do_something_with_response(response)
        pretty_print("CLIENT TEE", "Response processed")
        self.send_response(response)           
    
    def get_public_key(self):
        return self.public_signing_key  
    
    def request_nonce(self):
        pretty_print("CLIENT TEE", "Requesting nonce")
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
    
    def send_evidence_to_verifier(self, evidence):
        data = json.loads(evidence)
        evidence = data['evidence']
        nonce = data['nonce']
        request = generate_request(["verb", "route", "evidence", "nonce"], ["GET", "attestation", evidence, nonce])
        self.connection_with_verifier.send(request)
        attestation = self.connection_with_verifier.receive()   
        pretty_print("CLIENT TEE", "Received attestation", attestation)
        return attestation
    
    def send_evidence_to_db_proxy(self, evidence, pipeline_evidence, nonce, query):
        pretty_print("CLIENT TEE", f"Sending evidence to db proxy {evidence}, {nonce}")
        try:
            query["evidence"] = evidence
            query["pipeline"] = pipeline_evidence
            query["nonce"] = nonce
            response = json.dumps(query)
        except Exception as e:
            pretty_print("CLIENT TEE", f"Error {e}")
        # try:
        #     response = generate_request(["evidence", "pipeline", "nonce"], [evidence, pipeline_evidence ,nonce])
        # except Exception as e:
        #     pretty_print("CLIENT TEE", f"Error {e}")
        pretty_print("CLIENT TEE", "Sending evidence to db proxy", query)
        self.connection_with_db_proxy.send(response)
        response = self.connection_with_db_proxy.receive()
        pretty_print("CLIENT TEE", "Received response from db proxy", response)
        return response
        
    def verify_attestation(self, attestation):
        attestation = json.loads(attestation)
        pretty_print("CLIENT TEE", "Verifying attestation", attestation)
        attestation_siganture = attestation['attestation']
        attestation_siganture = base64.b64decode(attestation_siganture)
        pretty_print("CLIENT TEE", f"{attestation_siganture}")
        attestation = self.verifier_public_key.verify(attestation_siganture)
        pretty_print("CLIENT TEE", "Attestation verified", attestation)
        attestation_json = json.loads(attestation)
        expiration = attestation_json['expiration']
        if(time.time() > expiration):
            pretty_print("CLIENT TEE", "Attestation expired")
            return False
        else:
            pretty_print("CLIENT TEE", "Attestation valid")
            return attestation
    
    def generate_evidence(self, nonce):
        source_code = inspect.getsource(ClientTEE)
        evidence_hash = sha256(source_code.encode('utf-8') + from_json_to_bytes(nonce))
        pipeline_hash = sha256(self.loaded_pipeline.encode('utf-8') + from_json_to_bytes(nonce))
        pretty_print("CLIENT TEE", f"Evidence hash {evidence_hash}")

        evidence = self.private_signing_key.sign(evidence_hash)
        pipeline_evidence = self.private_signing_key.sign(pipeline_hash)

        pretty_print("CLIENT TEE", f"Evidence generated {evidence}")
        return evidence, pipeline_evidence
    
    
    def send_query(self, query):
        try:    
            pretty_print("CLIENT TEE", f"Sending query {query}")
            query = json.dumps(query)
            self.connection_with_db_proxy.send(query)
            response = self.connection_with_db_proxy.receive()
            return response
        except Exception as e:
            pretty_print("CLIENT TEE", f"Error sending query {e}")
            self.stop()
        
    def verify_response(self, response):
        pretty_print("CLIENT TEE", "Verifying response", response)
        response_json = json.loads(response)
        pretty_print("CLIENT TEE", f"Response {response_json["response"]}")
        if 'error' in response_json:
            pretty_print("CLIENT TEE", f"Error in response: {response_json['error']}")
            return
        pretty_print("CLIENT TEE", f"Verifying response {response_json}")
        query_result = None
        try:
            query_result = self.db_tee_public_key.verify(base64.b64decode(response_json['response']))
            pretty_print("CLIENT TEE", f"Query verified {query_result}")
        except Exception as e:
            pretty_print("CLIENT TEE", f"Query validation: {e}")
            return False
        pretty_print("CLIENT TEE", f"Response verified query result = {query_result}")
        return query_result
    
    def do_something_with_response(self, response):
        pretty_print("CLIENT TEE", "Doing something with response")
        return response
    
    def send_response(self, response):
        pretty_print("CLIENT TEE", f"Sending response here {response}")
        response = prepare_bytes_for_json(response)
        pretty_print("CLIENT TEE", f"Sending response {response}")
        response = generate_request(["response"], [response])
        pretty_print("CLIENT TEE", f"Sending response {response}")
        try:
            self.connection_with_client.send(response)
            pretty_print("CLIENT TEE", f"Response sent")
        except Exception as e:
            pretty_print("CLIENT TEE", f"Error sending response {e}")
            self.stop()
    
    def stop(self):
        response = generate_request(["close"], ["close"])
        self.connection_with_verifier.send(response)
        self.connection_with_db_proxy.send(response)
        try:
            self.connection_with_client.close()
            self.connection_with_verifier.close()
            self.connection_with_db_proxy.close()    
        except:
            print("Connections already closed")
        finally:
            return
    