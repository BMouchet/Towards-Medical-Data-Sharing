import base64
import json
import time
from TLS_helper import TLSHelper
from tools import generate_json_from_lists

class Client:
    def __init__(self, ca_cert_file, tee_public_key, verifier_public_key):
        self.connection_with_verifier = TLSHelper(ca_cert_file, is_server=False)
        self.connection_with_db_proxy = TLSHelper(ca_cert_file, is_server=False)
        self.tee_public_key = tee_public_key
        self.verifier_public_key = verifier_public_key
        self.nonce_freshness = None
    
    def start(self, tee_host, tee_port, verifier_host, verifier_port, query):
        try:
            self.connection_with_verifier.connect(verifier_host, verifier_port)
            self.connection_with_db_proxy.connect(tee_host, tee_port)
            start_time = time.time()
            query = json.loads(query)
            query_name = query["route"]
            nonce = self.request_nonce()
            self.nonce_freshness = time.time()
            evidence = self.request_evidence(nonce, query_name)
            attestation = self.send_evidence(evidence, nonce, query_name)
            if self.verify_attestation(attestation):
                query_result = self.send_query(query) 
                if "route" in query_result and "evidence" in query_result:
                    self.stop()
                    return "Attestation required, access denied"
                query_result = self.verify_response(query_result)
                duration = time.time() - start_time
                return query_result, duration
            else:
                return "Attestation failed"
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            return str(e)
        finally:
            self.stop()
    
    def request_nonce(self):
        request = generate_json_from_lists(["method", "route"], ["GET", "nonce"])
        self.connection_with_verifier.send(request)
        return self.connection_with_verifier.receive()
    
    def request_evidence(self, nonce, query_name):
        nonce = json.loads(nonce)["nonce"]
        request = generate_json_from_lists(["method", "route", "nonce", "query_name"], ["GET", "evidence", nonce, query_name])
        self.connection_with_db_proxy.send(request)
        return self.connection_with_db_proxy.receive()
        
    def send_evidence(self, evidence, nonce, query_name):
        evidence = json.loads(evidence)
        source_code_claim = evidence["source_code_claim"]
        loaded_pipeline_claim = evidence["loaded_pipeline_claim"]
        nonce = evidence["nonce"]
        request = generate_json_from_lists(["method", "route", "source_code_claim", "loaded_pipeline_claim", "nonce", "query_name"], ["GET", "attestation", source_code_claim, loaded_pipeline_claim, nonce, query_name])
        self.connection_with_verifier.send(request)
        return self.connection_with_verifier.receive()
    
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
        
    def send_query(self, query):
        self.connection_with_db_proxy.send(json.dumps(query))
        return self.connection_with_db_proxy.receive()
    
    def verify_response(self, response):
        try:
            response = json.loads(response)
            decoded_response = base64.b64decode(response["result"])
            verified_response = self.tee_public_key.verify(decoded_response)
            return verified_response
        except Exception as e:
            return str(e)
        
    def stop(self):
        try:
            close_request = generate_json_from_lists(["close"], ["close"])
            self.connection_with_verifier.send(close_request)
            self.connection_with_db_proxy.send(close_request)

            self.connection_with_verifier.close()
            self.connection_with_db_proxy.close()

        except Exception as e:
            pass