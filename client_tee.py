import base64
import datetime
import inspect
import json
import os
import time

import dotenv
from TLS_helper import TLSHelper
from display_helper import pretty_print
from nacl.signing import SigningKey
from nacl.hash import sha256
from pymongo import MongoClient

from tools import from_json_to_bytes, generate_request, prepare_bytes_for_json, write_data

class ClientTEE:
    def __init__(self, ca_cert_file, self_cert_file, key_file, db_tee_public_key, verifier_public_key):
        """
        Initialize the ClientTEE instance.

        :param ca_cert_file: Path to CA certificate file.
        :param self_cert_file: Path to self certificate file.
        :param key_file: Path to key file.
        :param db_tee_public_key: Public key of the database TEE.
        :param verifier_public_key: Public key of the verifier.
        """
        self.connection_with_verifier = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.connection_with_db_proxy = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.connection_with_client = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.verifier_public_key = verifier_public_key
        self.db_tee_public_key = db_tee_public_key
        self.private_signing_key = SigningKey.generate()
        self.public_signing_key = self.private_signing_key.verify_key
        self.listening = False
        self.pipeline_name = None
        self.pipeline = None
        self.methods = {"get_height": "get_height", "is_bp_above_mean": "get_bp"}
        
        client = MongoClient('localhost', 27017)
        db = client['data']
        self.bp = db['bp']
        self.pipelines = db['pipelines']
        self.start_time = None
        dotenv.load_dotenv()
        self.file = os.getenv('FILE')
        # pretty_print("CLIENT TEE", "Initialized")
        
    def get_public_key(self):
        """
        Get the public signing key.

        :return: Public signing key.
        """
        return self.public_signing_key
        
    def start(self, client_host, client_port, tee_host, tee_port, verifier_host, verifier_port):
        """
        Start the ClientTEE instance and listen for requests.

        :param client_host: Host address of the client.
        :param client_port: Port of the client.
        :param tee_host: Host address of the TEE.
        :param tee_port: Port of the TEE.
        :param verifier_host: Host address of the verifier.
        :param verifier_port: Port of the verifier.
        """
        self.connection_with_client.connect(client_host, client_port)
        self.connection_with_verifier.connect(verifier_host, verifier_port)
        self.connection_with_db_proxy.connect(tee_host, tee_port)
        self.listening = True
        
        while self.listening:
            request = self.connection_with_client.receive()
            self.dispatch_request(request)
        
    def dispatch_request(self, request):
        """
        Dispatch the received request to the appropriate handler.

        :param request: The received request.
        """
        request_json = json.loads(request)  
        # pretty_print("CLIENT TEE", "Received request", request_json)
        try:
            if request_json['verb'] == 'GET' and request_json['route'] in self.methods:
                self.execute_query(request_json)
        except:
            if 'error' in request_json or 'close' in request_json:
                # pretty_print("Client TEE", "Received close request")
                self.listening = False
                self.stop()
                
    def execute_query(self, query):
        """
        Execute the query after attestation protocol.

        :param query: The query to be executed.
        :return: The response of the query.
        """
        self.start_attestation_protocol(query)
        response = generate_request(["response"], ["response"])
        return response
    
    def start_attestation_protocol(self, query):
        """
        Start the attestation protocol for the given query.

        :param query: The query to be attested.
        """
        self.start_time = time.time()
        nonce = self.request_nonce()
        duration = time.time() - self.start_time
        write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Client TEE nonce request", duration])

        # pretty_print("CLIENT TEE", "Received nonce", nonce)
        self.start_time = time.time()
        evidence_requested = self.request_evidence(nonce)
        # pretty_print("CLIENT TEE", "Received evidence", evidence_requested)
        attestation = self.send_evidence_to_verifier(evidence_requested)
        duration = time.time() - self.start_time
        write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Client TEE evidence request", duration])
        # pretty_print("CLIENT TEE", "Received attestation", attestation)
        self.start_time = time.time()
        attestation = self.verify_attestation(attestation)
        duration = time.time() - self.start_time
        write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Client TEE attestation verification", duration])
        if not attestation:
            # pretty_print("CLIENT TEE", "Attestation failed")
            self.stop()
            return
        # pretty_print("CLIENT TEE", "Attestation succeeded, sending query")
        response = self.send_query(query)
        self.start_time = time.time()
        # pretty_print("CLIENT TEE", f"Is contained ? {'evidence' in response}")
        response_json = json.loads(response)
        if 'evidence' in response:
            self.pipeline = self.pipelines.find_one({"name": self.pipeline_name})["pipeline"]
            nonce = response_json['nonce']
            evidence_requested, pipeline_evidence = self.generate_evidence(nonce)
            evidence_requested = prepare_bytes_for_json(evidence_requested)
            pipeline_evidence = prepare_bytes_for_json(pipeline_evidence)
            # pretty_print("CLIENT TEE", "Evidence generated")
            response = self.send_evidence_to_db_proxy(evidence_requested, pipeline_evidence, nonce, query)
            self.start_time = time.time()
            # pretty_print("CLIENT TEE", "Response received")
            response = self.verify_response(response)
            # pretty_print("CLIENT TEE", "Response verified")
            response = self.process_response(response)
            # pretty_print("CLIENT TEE", "Response processed")
            duration = time.time() - self.start_time
            write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Client TEE response with process", duration])
        else:
            response = self.verify_response(response)
            duration = time.time() - self.start_time
            write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Client TEE simple response verification", duration])
            # pretty_print("CLIENT TEE", "Response verified")
        self.send_response(response)           
    
    def get_public_key(self):
        """
        Get the public signing key.

        :return: Public signing key.
        """
        return self.public_signing_key  
    
    def request_nonce(self):
        """
        Request a nonce from the verifier.

        :return: The received nonce.
        """
        # pretty_print("CLIENT TEE", "Requesting nonce")
        request = generate_request(["verb", "route"], ["GET", "nonce"])
        self.connection_with_verifier.send(request)
        nonce = self.connection_with_verifier.receive()
        return nonce
    
    def request_evidence(self, nonce):
        """
        Request evidence from the database proxy using the nonce.

        :param nonce: The nonce to be used.
        :return: The received evidence.
        """
        nonce = json.loads(nonce)['nonce']
        request = generate_request(["verb", "route", "nonce"], ["GET", "evidence", nonce])
        self.connection_with_db_proxy.send(request)
        evidence = self.connection_with_db_proxy.receive()
        return evidence
    
    def send_evidence_to_verifier(self, evidence):
        """
        Send the received evidence to the verifier.

        :param evidence: The evidence to be sent.
        :return: The received attestation.
        """
        data = json.loads(evidence)
        evidence = data['evidence']
        nonce = data['nonce']
        request = generate_request(["verb", "route", "evidence", "nonce"], ["GET", "attestation", evidence, nonce])
        self.connection_with_verifier.send(request)
        attestation = self.connection_with_verifier.receive()   
        # pretty_print("CLIENT TEE", "Received attestation", attestation)
        return attestation
    
    def send_evidence_to_db_proxy(self, evidence, pipeline_evidence, nonce, query):
        """
        Send the evidence and pipeline evidence to the database proxy.

        :param evidence: The evidence to be sent.
        :param pipeline_evidence: The pipeline evidence to be sent.
        :param nonce: The nonce to be used.
        :param query: The query to be sent.
        :return: The received response.
        """
        # pretty_print("CLIENT TEE", f"Sending evidence to db proxy {evidence}, {nonce}")
        try:
            query["pipeline_name"] = self.pipeline_name
            query["evidence"] = evidence
            query["pipeline"] = pipeline_evidence
            query["nonce"] = nonce
            response = json.dumps(query)
        except Exception as e:
            # pretty_print("CLIENT TEE", f"Error {e}")
            pass
        # pretty_print("CLIENT TEE", "Sending evidence to db proxy", query)
        self.connection_with_db_proxy.send(response)
        duration = time.time() - self.start_time
        write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Client TEE evidence generation", duration])
        response = self.connection_with_db_proxy.receive()
        # pretty_print("CLIENT TEE", "Received response from db proxy", response)
        return response
        
    def verify_attestation(self, attestation):
        """
        Verify the received attestation.

        :param attestation: The attestation to be verified.
        :return: The verified attestation or False if verification fails.
        """
        attestation = json.loads(attestation)
        # pretty_print("CLIENT TEE", "Verifying attestation", attestation)
        attestation_siganture = attestation['attestation']
        attestation_siganture = base64.b64decode(attestation_siganture)
        # pretty_print("CLIENT TEE", f"{attestation_siganture}")
        attestation = self.verifier_public_key.verify(attestation_siganture)
        # pretty_print("CLIENT TEE", "Attestation verified", attestation)
        attestation_json = json.loads(attestation)
        expiration = attestation_json['expiration']
        if(time.time() > expiration):
            # pretty_print("CLIENT TEE", "Attestation expired")
            return False
        else:
            # pretty_print("CLIENT TEE", "Attestation valid")
            return attestation
    
    def generate_evidence(self, nonce):
        """
        Generate evidence using the nonce.

        :param nonce: The nonce to be used.
        :return: The generated evidence and pipeline evidence.
        """
        try:
            source_code = inspect.getsource(ClientTEE)
            evidence_hash = sha256(source_code.encode('utf-8') + from_json_to_bytes(nonce))
            pipeline_hash = sha256(str(self.pipeline).encode('utf-8') + from_json_to_bytes(nonce))
            # pretty_print("CLIENT TEE", f"Evidence hash {evidence_hash}")

            evidence = self.private_signing_key.sign(evidence_hash)
            pipeline_evidence = self.private_signing_key.sign(pipeline_hash)

            # pretty_print("CLIENT TEE", f"Evidence generated {evidence}")
            return evidence, pipeline_evidence
        except Exception as e:
            pretty_print("CLIENT TEE", f"Error generating evidence {e}")
            
    
    def send_query(self, query):
        """
        Send the query to the database proxy.

        :param query: The query to be sent.
        :return: The received response.
        """
        try:    
            self.pipeline_name = query["route"]
            # pretty_print("CLIENT TEE", f"Sending query {query}")
            query["route"] = self.methods[query["route"]]
            query = json.dumps(query)
            self.connection_with_db_proxy.send(query)
            response = self.connection_with_db_proxy.receive()
            return response
        except Exception as e:
            pretty_print("CLIENT TEE", f"Error sending query {e}")
            self.stop()
        
    def verify_response(self, response):
        """
        Verify the received response.

        :param response: The response to be verified.
        :return: The verified query result or False if verification fails.
        """
        # pretty_print("CLIENT TEE", "Verifying response", response)
        response_json = json.loads(response)
        # pretty_print("CLIENT TEE", f"Response {response_json['response']}")
        if 'error' in response_json:
            pretty_print("CLIENT TEE", f"Error in response: {response_json['error']}")
            return
        # pretty_print("CLIENT TEE", f"Verifying response {response_json}")
        query_result = None
        try:
            query_result = self.db_tee_public_key.verify(base64.b64decode(response_json['response']))
            # pretty_print("CLIENT TEE", f"Query verified {query_result}")
        except Exception as e:
            pretty_print("CLIENT TEE", f"Query validation: {e}")
            return False
        # pretty_print("CLIENT TEE", f"Response verified query result = {query_result}")
        return query_result
    
    def process_response(self, response):
        """
        Process the received response.

        :param response: The response to be processed.
        :return: The processed response.
        """
        # pretty_print("CLIENT TEE", f"Processing response {response}")
        data = response.decode('utf-8')
        data = json.loads(data)
        data = data[0]['bp']
        pipeline = self.prepare_pipeline({"input_bp": data})
        response = list(self.bp.aggregate(pipeline))
        return str(response).encode('utf-8')
    
    def send_response(self, response):
        """
        Send the response to the client.

        :param response: The response to be sent.
        """
        # pretty_print("CLIENT TEE", f"Sending response here {response}")
        response = prepare_bytes_for_json(response)
        # pretty_print("CLIENT TEE", f"Sending response {response}")
        response = generate_request(["response"], [response])
        # pretty_print("CLIENT TEE", f"Sending response {response}")
        try:
            self.connection_with_client.send(response)
            # pretty_print("CLIENT TEE", f"Response sent")
        except Exception as e:
            pretty_print("CLIENT TEE", f"Error sending response {e}")
            self.stop()
    
    def prepare_pipeline(self, params):
        """
        Prepare the pipeline with the given parameters.

        :param params: The parameters to be used.
        :return: The prepared pipeline.
        """
        try:
            pipeline_template = self.pipeline
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

            return replace_placeholders(pipeline_template)
        except Exception as e:
            pretty_print("CLIENT TEE", f"Error preparing pipeline {e}")
    
    def validate_param(self, param_name, param_value):
        """
        Validate the given parameter.

        :param param_name: The name of the parameter.
        :param param_value: The value of the parameter.
        :return: The validated parameter value.
        :raises ValueError: If the parameter name or value is invalid.
        """
        if param_name in ["input_bp"]:
            if not isinstance(param_value, (int, float)):
                raise ValueError(f"Invalid parameter value for {param_name}: {param_value}")
            return param_value
        else:
            raise ValueError(f"Invalid parameter name: {param_name}")

    
    def stop(self):
        """
        Stop the ClientTEE instance and close all connections.
        """
        response = generate_request(["close"], ["close"])
        self.connection_with_verifier.send(response)
        self.connection_with_db_proxy.send(response)
        try:
            self.connection_with_client.close()
            self.connection_with_verifier.close()
            self.connection_with_db_proxy.close()    
        except:
            pass
        finally:
            return