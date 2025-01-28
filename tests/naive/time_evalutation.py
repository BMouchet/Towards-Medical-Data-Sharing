import csv
import datetime
import json
import os
from bson import ObjectId
import dotenv
from pymongo import MongoClient
from TLS_helper import TLSHelper
from tools import generate_request
import threading
import queue
import time

doctor_id = ObjectId('000000000000000000000000')
patient_id = ObjectId('111111111111111111111111')
external_id = ObjectId('222222222222222222222222')

class Test_client:
    def __init__(self, ca_cert_file):
        self.connection_with_db = TLSHelper(ca_cert_file, is_server=False)
        
    def start(self, user_id, patient_id, attestation):
        try:
            self.connection_with_db.connect("localhost", 12345)
            start_time = time.time()
            request = generate_request(["verb", "route", "patient_id", "user_id", "attestation"], ["GET", "test", str(patient_id), str(user_id), attestation])
            self.connection_with_db.send(request)
            response = self.connection_with_db.receive()
            duration = time.time() - start_time
            return response, duration
        except Exception as e:
            return str(e)
        finally:
            self.stop()
            
    def stop(self):
        try:    
            self.connection_with_db.close()
        except:
            pass
        
class DB:
    def __init__(self, ca_cert_file, self_cert_file, key_file):
        self.connection_with_client = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        dotenv.load_dotenv()
        username = os.getenv('TEE_DB_USERNAME')
        password = os.getenv('TEE_DB_PASSWORD')
        uri = f'mongodb://{username}:{password}@localhost:27017/'
        self.client = MongoClient(uri)
        self.db = self.client['test_dataset']
    
    def start(self):
        try:
            self.connection_with_client.connect("localhost", 12345)
            request = self.connection_with_client.receive()
            request = json.loads(request)
            if request["route"] == "test":
                patient_data = self.db['patients']
                
                patient_id = ObjectId(request["patient_id"])
                user_id = ObjectId(request["user_id"])
                user = self.db.users.find_one({"_id": user_id, "password": "password"}) 
                user_id = user["_id"]
                attestation = request["attestation"]
                bp = None
                patient_data_ = patient_data.find_one({"patientId": patient_id})
                if patient_id == user_id:
                    bp = patient_data_["data"]["metrics"]["sensitiveMetrics"]["bloodPressure"]
                else:
                    bp_ac_id = patient_data_["data"]["metrics"]["sensitiveMetrics"]["accessControl"]
                    ac = self.db.accessControls.find_one({"_id": bp_ac_id}) 
                    users = ac["users"]
                    user_access = next((user for user in users if user["userId"] == user_id), None)
                    if user_access and user_access["expiration"] > datetime.datetime.now():
                        if "read" in user_access["permissions"]:
                            bp = patient_data_["data"]["metrics"]["sensitiveMetrics"]["bloodPressure"]
                        else:
                            if attestation and "enclave" in user_access["permissions"]:
                                bp = patient_data_["data"]["metrics"]["sensitiveMetrics"]["bloodPressure"]
                            else:
                                bp = "Attestation required"
                    else:
                        bp = "Access denied"
                mean_pipeline = {"$group": {"_id": None, "mean": {"$avg": "$bp"} }}
                mean_bp = list(self.db.bps.aggregate([mean_pipeline]))[0]["mean"]
                comparison = "higher" if bp > mean_bp else "lower"
                response = generate_request(["response", "mean_bp", "comparison"], [bp, mean_bp, comparison])
                self.connection_with_client.send(response)
        except Exception as e:
            print(f"Error occurred: {str(e)}")


ca_cert_file = "../certs/ca-cert.pem"
client_key_file = "../certs/client-key.pem"
server_key_file = "../certs/server-key.pem"
server_cert_file = "../certs/server-cert.pem"

def run_client(user_id, result_queue):
    client = Test_client(ca_cert_file)
    result = client.start(user_id, patient_id, True)
    result_queue.put(result)  # Put the result into the queue
    

def run_db():
    db = DB(ca_cert_file, server_cert_file, server_key_file)
    db.start()

if __name__ == "__main__":
    tries = 100
    user_ids = [external_id]
    csv_file = "results.csv"

    for i in range(tries):
        for user_id in user_ids:
            result_queue = queue.Queue()  
            # Create threads
            client_thread = threading.Thread(target=run_client, args=(user_id, result_queue))
            db_thread = threading.Thread(target=run_db)

            db_thread.start()
            client_thread.start()

            db_thread.join()
            client_thread.join()

            # Get the actual result from the queue
            client_result = result_queue.get()

            # Write results to CSV
            with open(csv_file, mode="a", newline="") as file:
                writer = csv.writer(file)
                writer.writerow([
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Current timestamp
                    user_id,
                    client_result[0],
                    client_result[1]
                ])
            print(f"Attempt {i + 1}/{tries} for user {user_id}: {client_result[0]} (Elapsed time: {client_result[1]} seconds) with result {client_result}")
            # Wait before the next iteration
            time.sleep(1)
