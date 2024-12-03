import base64
import datetime
import time

from bson import ObjectId
from TLS_helper import TLSHelper
from pymongo import MongoClient
import json
from display_helper import pretty_print

class Database:
    def __init__(self, ca_cert_file, self_cert_file, key_file, verifier_public_key=None):
        self.secure_connection = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.client = MongoClient('localhost', 27017)
        self.db = self.client['mydb']
        self.users = self.db['users']
        self.patient_data = self.db['patient_data']
        self.authorizations = self.db['authorizations']
        self.tee_public_key = None
        self.verifier_public_key = verifier_public_key
        self.populate_db()
    
    def listen(self, host, port):
        self.secure_connection.connect(host, port)
        request = self.secure_connection.receive()
        pretty_print("DATABASE", "Received request", request)

        # Validate TEE attestation
        if not self.validate_attestation(request):
            pretty_print("DATABASE", "Invalid TEE attestation")
            self.secure_connection.send(json.dumps({"error": "Invalid TEE attestation"}).encode('utf-8'))
            return

        # Authenticate user
        user = self.authenticate_user(request)
        if not user:
            pretty_print("DATABASE", "Authentication failed")
            self.secure_connection.send(json.dumps({"error": "Authentication failed"}).encode('utf-8'))
            return

        # Authorize user
        if not self.check_authorization(user, request):
            pretty_print("DATABASE", "Authorization failed")
            self.secure_connection.send(json.dumps({"error": "Authorization failed"}).encode('utf-8'))
            return

        # Query database
        db_response = self.query_db(request)
        db_response = {"response": db_response}
        db_response = json.dumps(db_response).encode('utf-8')
        pretty_print("DATABASE", "Sending response", db_response)
        self.secure_connection.send(db_response)
        
    def validate_attestation(self, request):
        """Validate the TEE attestation"""
        attestation = json.loads(request)
        attestation = json.loads(attestation["attestation"])
        if not attestation:
            return False
        try:
            expiration_time = base64.b64decode(attestation['expiration'])
            expiration_time = self.verifier_public_key.verify(expiration_time)
            if time.time() - float(expiration_time) > 300:
                pretty_print("DATABASE", "Attestation expired")
                return False
            attestation = base64.b64decode(attestation['attestation'])
            attestation = self.verifier_public_key.verify(attestation)
            return attestation
        except Exception as e:
            pretty_print("DATABASE", f"Attestation validation: {e}")
            return False

    def authenticate_user(self, request):
        """Authenticate the user using their credentials"""
        credentials = json.loads(request)
        if not credentials or "username" not in credentials or "password" not in credentials:
            pretty_print("DATABASE", "Invalid credentials")
            return None
        user = self.users.find_one({"avs": credentials["username"], "password": credentials["password"]})
        pretty_print("DATABASE", f"Authenticated user {user}")
        return user

    def check_authorization(self, user, request):
        """Check if the authenticated user is authorized to access the data"""
        pipeline = json.loads(request)
        pipeline = pipeline["pipeline"]
        avs = None
        for stage in pipeline:
            if "$match" in stage and "avs" in stage["$match"]:
                avs = stage["$match"]["avs"]
                break

        if not avs:  # If AVS is not found in the pipeline, authorization fails
            pretty_print("DATABASE", "Authorization failed: no AVS found in pipeline")
            return False
        # Find the patient user by AVS
        patient_user = self.users.find_one({"avs": avs})
        if not patient_user:  # If no patient with the AVS exists, authorization fails
            pretty_print("DATABASE", f"Authorization failed: no user found with AVS {avs}")
            return False
        pretty_print("DATABASE", f"Checking authorization for user {user} to access patient {patient_user}")
        # Check authorization for the requested patient
        authorization = None
        if patient_user == user:
            authorization = True
        authorization = self.authorizations.find_one({
            "patient_id": patient_user["_id"],
            "doctor_id": user["_id"],
            "access_type": "read",
            "expiration": {"$gte": datetime.datetime.utcnow()}
        })
        return authorization is not None
    
    def query_db(self, request):
        request = json.loads(request)
        pipeline = request["pipeline"]
        pretty_print("DATABASE", f"Querying database with pipeline",pipeline)
        result = self.patient_data.aggregate(pipeline)
        return list(result)
    
    def close_connection(self):
        try:
            self.secure_connection.close()
        except Exception as e:
            pretty_print("DATABASE", f"Error closing connection: {e}")
        
    def populate_db(self):
        if self.users.count_documents({}) == 0:
            users = [
                {
                    "_id": ObjectId(),
                    "avs": "756.1111.1111.11",
                    "password": "Password",
                    "first_name": "Ben",
                    "last_name": "Doe",
                    "role": "patient",
                    "created_at": time.time(),
                    "updated_at": time.time()
                },
                {
                    "_id": ObjectId(),
                    "avs": "756.1111.1111.12",
                    "password": "Password",
                    "first_name": "Ben",
                    "last_name": "Smith",
                    "role": "doctor",
                    "created_at": time.time(),
                    "updated_at": time.time()
                },
                {
                    "_id": ObjectId(),
                    "avs": "756.1111.1111.13",
                    "password": "Password",
                    "first_name": "Ben",
                    "last_name": "Johnson",
                    "role": "admin",
                    "created_at": time.time(),
                    "updated_at": time.time()
                },
                {
                    "_id": ObjectId(),
                    "avs": "756.1111.1111.14",
                    "password": "Password",
                    "first_name": "Ben",
                    "last_name": "Brown",
                    "role": "state",
                    "created_at": time.time(),
                    "updated_at": time.time()
                },
                {
                    "_id": ObjectId(),
                    "avs": "756.111.1111.15",
                    "password": "Password",
                    "first_name": "Ben",
                    "last_name": "Green",
                    "role": "commercial",
                    "created_at": time.time(),
                    "updated_at": time.time()
                }                
            ]
            self.users.insert_many(users)
            print("Users:")
            for user in self.users.find():
                print(user)

        if self.patient_data.count_documents({}) == 0:
            # Retrieve the patient user's _id using their AVS number
            patient_user = self.users.find_one({"avs": "756.1111.1111.11"})
            if patient_user:  # Ensure the user exists before proceeding
                patient_data = [
                    {
                        "_id": ObjectId(),
                        "avs": "756.1111.1111.11",
                        "date_of_birth": "01/01/2000",
                        "height": "185",
                        "weight": "80",
                        "blood_type": "A+",
                        "confidential_data": {
                            "blood_pressure": "120/80",
                            "medication": "Ibuprofen"
                        },
                        "owner_id": patient_user["_id"]  # Link the patient to the user
                    }
                ]
                self.patient_data.insert_many(patient_data)
            print("Patients:")
            for patient in self.patient_data.find():
                print(patient)
                
        if self.authorizations.count_documents({}) == 0:
            # Retrieve the patient user's _id for authorizations
            patient_user = self.users.find_one({"avs": "756.1111.1111.11"})
            doctor = self.users.find_one({"avs": "756.1111.1111.12"})
            if patient_user:  # Ensure the user exists before proceeding
                authorizations = [
                    {
                        "_id": ObjectId(),
                        "patient_id": patient_user["_id"],  # Link to the patient's user ID
                        "doctor_id": doctor["_id"],  # Link to the doctor's user ID
                        "access_type": "read",
                        "expiration": datetime.datetime.now() + datetime.timedelta(days=30),
                    }
                ]
                self.authorizations.insert_many(authorizations)

            print("Authorizations:")
            for auth in self.authorizations.find():
                print(auth)

    def delete_collections(self):
        self.users.drop()
        self.patient_data.drop()
        self.authorizations.drop()
        print("Collections deleted")
        
if __name__ == "__main__":
    database = Database(ca_cert_file="certs/ca-cert.pem", self_cert_file="certs/server-cert.pem", key_file="certs/server-key.pem")
    database.delete_collections()
    database.populate_db()