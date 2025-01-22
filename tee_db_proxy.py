import base64
import copy
import datetime
import inspect
import json
import time
from bson import ObjectId
from TLS_helper import TLSHelper
from tools import generate_request, prepare_bytes_for_json, from_json_to_bytes, write_data
from display_helper import pretty_print
from nacl.signing import SigningKey
from nacl.hash import sha256
from pymongo import MongoClient
import os
import dotenv


class TEE_DB_Proxy:
    def __init__(self, ca_cert_file, self_cert_file, key_file, verifier_public_key):
        """
        Initialize the TEE_DB_Proxy.

        :param ca_cert_file: Path to the CA certificate file.
        :param self_cert_file: Path to the self certificate file.
        :param key_file: Path to the key file.
        :param verifier_public_key: Public key of the verifier.
        """
        self.connection_with_client = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.connection_with_verifier = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.listening = False
        self.private_signing_key = SigningKey.generate()
        self.public_signing_key = self.private_signing_key.verify_key
        self.verifier_public_key = verifier_public_key
        # pretty_print("TEE DB PROXY", "Initialized")
        self.methods = {
            "get_height",
            "get_bp"
        }
        dotenv.load_dotenv()
        username = os.getenv('TEE_DB_USERNAME')
        password = os.getenv('TEE_DB_PASSWORD')
        self.uri = f'mongodb://{username}:{password}@localhost:27017/'
        self.pipeline = None
        self.client = MongoClient(self.uri)
        self.db = self.client['medical-data']
        self.start_time = None
        self.file = os.getenv('FILE')
        
    def get_public_key(self):
        """
        Get the public signing key.

        :return: Public signing key.
        """
        return self.public_signing_key

    def start(self, tee_host, tee_port, verifier_host, verifier_port):
        """
        Start the TEE DB Proxy.

        :param tee_host: Host for the TEE.
        :param tee_port: Port for the TEE.
        :param verifier_host: Host for the verifier.
        :param verifier_port: Port for the verifier.
        """
        self.connection_with_client.connect(tee_host, tee_port)
        if verifier_host and verifier_port:
            self.connection_with_verifier.connect(verifier_host, verifier_port)
            # pretty_print("TEE DB PROXY", "Connected to verifier")
        self.listening = True

        while self.listening:
            request = self.connection_with_client.receive()
            self.dispatch_request(request)

    def dispatch_request(self, request):
        """
        Dispatch the received request.

        :param request: The request received from the client.
        """
        request_json = json.loads(request)
        # pretty_print("TEE DB PROXY", "Received request", request_json)
        try:
            if request_json['verb'] == 'GET' and request_json['route'] == 'evidence':
                self.start_time = time.time()
                nonce = request_json['nonce']
                evidence = prepare_bytes_for_json(self.generate_evidence(request_json['nonce']))
                self.send_evidence(evidence, nonce)
                duration = time.time() - self.start_time
                write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Evidence generation Proxy", duration ])
            elif request_json['verb'] == 'GET' and request_json['route'] in self.methods:
                self.start_time = time.time()
                request_json['params']["attestation"] = False
                response = self.execute_query(request_json)
                # pretty_print("TEE DB PROXY", f"Response {response}")
                if any("attestation required" in item.values() for item in response):
                    duration = time.time() - self.start_time
                    write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Query execution Proxy attestation required", duration])
                    attestation = self.start_attestation_protocol()
                    self.start_time = time.time()
                    attestation = self.verify_attestation(attestation)
                    if attestation:
                        # pretty_print("TEE DB PROXY", "Attestation successful added to params")
                        request_json['params']["attestation"] = True
                        # pretty_print("TEE DB PROXY", f"Request with attestation {request_json}")
                        response = self.execute_query(request_json)
                        # pretty_print("TEE DB PROXY", f"Response {response}")
                        signed_result = self.sign_response(response)
                        # pretty_print("TEE DB PROXY", f"Query result {signed_result}")
                        response = generate_request(["response"], [prepare_bytes_for_json(signed_result)])
                        self.send_response(response)
                    else:
                        response = generate_request(["error"], ["Attestation failed"])
                        self.send_response(response)
                        self.stop()
                    duration = time.time() - self.start_time
                    write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Query execution Proxy with attestation", duration])
                else:
                    signed_result = self.sign_response(response)
                    # pretty_print("TEE DB PROXY", f"Query result {signed_result}")
                    response = generate_request(["response"], [prepare_bytes_for_json(signed_result)])
                    self.send_response(response)
                    duration = time.time() - self.start_time
                    write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Query execution Proxy no attestation", duration])
            
        except Exception as e:
            # pretty_print("TEE DB PROXY", f"Error: {e}")
            # if 'error' in request_json or 'close' in request_json:
                # pretty_print("TEE DB PROXY", "Received close request")
            self.listening = False
            self.stop()

    def generate_evidence(self, nonce):
        """
        Generate evidence for the given nonce.

        :param nonce: Nonce to be included in the evidence.
        :return: Signed evidence.
        """
        source_code = inspect.getsource(TEE_DB_Proxy)
        evidence_hash = sha256(source_code.encode('utf-8') + from_json_to_bytes(nonce))
        # pretty_print("TEE DB PROXY", f"Generated evidence {evidence_hash}")
        evidence = self.private_signing_key.sign(evidence_hash)
        return evidence

    def send_evidence(self, evidence, nonce):
        """
        Send the generated evidence to the client.

        :param evidence: The generated evidence.
        :param nonce: The nonce used to generate the evidence.
        """
        response = generate_request(["evidence", "nonce"], [evidence, nonce])
        self.connection_with_client.send(response)

    def execute_query(self, query):
        """
        Execute the query on the database.

        :param query: The query to be executed.
        :return: The result of the query.
        """
        # pretty_print("TEE DB PROXY", f"Executing query {query}")
        user = self.authenticate_user(query['username'], query['password'])
        query['params']['user_id'] = user
        pipeline = self.get_pipeline(query['route'], query['params'])
        result = list(self.db.patients.aggregate(pipeline))
        if any("attestation required" in item.values() for item in result):
            # pretty_print("TEE DB PROXY", "Attestation required")
            return result
        return result

    def sign_response(self, response):
        """
        Sign the response.

        :param response: The response to be signed.
        :return: The signed response.
        """
        # pretty_print("TEE DB PROXY", "Signing response", response)
        response = json.dumps(response)
        response = response.encode('utf-8')
        signature = self.private_signing_key.sign(response)
        return signature

    def authenticate_user(self, username, password):
        """
        Authenticate the user.

        :param username: The username of the user.
        :param password: The password of the user.
        :return: The user ID if authentication is successful.
        :raises ValueError: If the username or password is invalid.
        """
        user = self.db.users.find_one({"username": username, "password": password})
        if user:
            return user["_id"]
        else:
            raise ValueError("Invalid username or password")

    def get_pipeline(self, template_name, params):
        """
        Get the pipeline for the given template name and parameters.

        :param template_name: The name of the pipeline template.
        :param params: The parameters for the pipeline.
        :return: The pipeline with placeholders replaced by parameter values.
        """
        pipeline_template = self.db.pipelines.find_one({"name": template_name})["pipeline"]
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

    def validate_param(self, param_name, param_value):
        """
        Validate the parameter value.

        :param param_name: The name of the parameter.
        :param param_value: The value of the parameter.
        :return: The validated parameter value.
        :raises ValueError: If the parameter value is invalid.
        """
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
        elif param_name == "access_type":
            valid_access_types = [["write"], ["read", "write"], ["read"]]
            if param_value not in valid_access_types:
                raise ValueError(f"Invalid access type: {param_value}")
            return param_value
        elif param_name == "height_input":
            if not isinstance(param_value, (int, float)):
                raise ValueError(f"Invalid height input: {param_value}")
            return param_value
        elif param_name == "attestation":
            if not isinstance(param_value, bool):
                raise ValueError(f"Invalid attestation value: {param_value}")
            return param_value
        elif param_name == "expiration":
            if isinstance(param_value, str):
                try:
                    # Assuming the datetime format is "YYYY-MM-DD HH:MM:SS"
                    expiration_datetime = datetime.datetime.strptime(param_value, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    raise ValueError(f"Invalid expiration time format: {param_value}. Expected format is YYYY-MM-DD HH:MM:SS")
            elif isinstance(param_value, datetime.datetime):
                expiration_datetime = param_value
            else:
                raise ValueError(f"Invalid expiration time: {param_value}. It should be a datetime or a valid datetime string.")
            # Optionally, compare expiration to current time to check if it's in the future
            if expiration_datetime <= datetime.datetime.now():
                raise ValueError(f"Expiration time must be in the future: {param_value}")
            # Return the expiration datetime object
            return expiration_datetime
        else:
            raise ValueError(f"Invalid parameter name: {param_name}")

    def send_response(self, response):
        """
        Send the response to the client.

        :param response: The response to be sent.
        """
        # pretty_print("TEE DB PROXY", "Sending response", response)
        self.connection_with_client.send(response)

    def start_attestation_protocol(self):
        """
        Start the attestation protocol.

        :return: The attestation result.
        """
        # pretty_print("TEE DB PROXY", "Starting attestation protocol")
        nonce = self.request_nonce()
        # pretty_print("TEE DB PROXY", "Received nonce", nonce)
        self.start_time = time.time()
        evidence = self.request_evidence(nonce)
        # pretty_print("TEE DB PROXY", "Received evidence", evidence)
        attestation = self.send_evidence_to_verifier(evidence)
        return attestation

    def request_nonce(self):
        """
        Request a nonce from the verifier.

        :return: The received nonce.
        """
        # pretty_print("TEE DB PROXY", "Requesting nonce")
        request = generate_request(["verb", "route"], ["GET", "nonce"])
        self.connection_with_verifier.send(request)
        nonce = self.connection_with_verifier.receive()
        return nonce

    def request_evidence(self, nonce):
        """
        Request evidence from the client using the given nonce.

        :param nonce: The nonce to be included in the evidence request.
        :return: The received evidence.
        """
        nonce = json.loads(nonce)['nonce']
        request = generate_request(["verb", "route", "nonce"], ["GET", "evidence", nonce])
        self.connection_with_client.send(request)
        duration = time.time() - self.start_time
        write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Evidence request Proxy", duration])
        evidence = self.connection_with_client.receive()
        if "error" in evidence:
            self.stop()
        return evidence

    def send_evidence_to_verifier(self, evidence):
        """
        Send the evidence to the verifier.

        :param evidence: The evidence to be sent.
        :return: The attestation result.
        """
        data = json.loads(evidence)
        evidence = data['evidence']
        nonce = data['nonce']
        pipeline_evidence = data['pipeline']
        pipeline_name = data['pipeline_name']
        request = generate_request(["verb", "route", "pipeline", "evidence", "pipeline_evidence", "nonce"], ["GET", "attestation", pipeline_name, evidence, pipeline_evidence, nonce])
        self.connection_with_verifier.send(request)
        attestation = self.connection_with_verifier.receive()
        return attestation

    def stop(self):
        """
        Stop the TEE DB Proxy.
        """
        response = generate_request(["close"], ["close"])
        self.connection_with_client.send(response)
        try:
            self.connection_with_client.close()
            self.connection_with_verifier.close()
        except Exception:
            pass

    def verify_attestation(self, attestation):
        """
        Verify the attestation.

        :param attestation: The attestation to be verified.
        :return: The verified attestation if valid, otherwise False.
        """
        attestation = json.loads(attestation)
        attestation_signature = attestation['attestation']
        attestation_signature = base64.b64decode(attestation_signature)
        attestation = self.verifier_public_key.verify(attestation_signature)
        attestation_json = json.loads(attestation)
        expiration = attestation_json['expiration']
        if time.time() > expiration:
            pretty_print("TEE DB PROXY", "Attestation expired")
            return False
        else:
            # pretty_print("TEE DB PROXY", "Attestation valid")
            return attestation
