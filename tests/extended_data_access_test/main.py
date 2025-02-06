import csv
import datetime
import queue
import threading
import time
from client import Client
from tee_db_proxy import TEE_DB_Proxy
from verifier import Verifier
from client_tee import ClientTEE

from tools import generate_json_from_lists

host = "127.0.0.1"
client_port = 12345
verifier_port = 12346
tee_port = 12347
client_tee_port = 12348
other_verifier_port = 12349
ca_cert_file = "certs/ca-cert.pem"
client_key_file = "certs/client-key.pem"
server_key_file = "certs/server-key.pem"
server_cert_file = "certs/server-cert.pem"

verifier = Verifier(ca_cert_file, server_cert_file, server_key_file)
tee_db_proxy = TEE_DB_Proxy(ca_cert_file, server_cert_file, server_key_file, verifier.get_public_key())
client_tee = ClientTEE(ca_cert_file, server_cert_file, server_key_file, tee_db_proxy.get_public_key(), verifier.get_public_key())
client = Client(ca_cert_file)
verifier.set_tee_public_key(tee_db_proxy.get_public_key())
verifier.set_client_tee_public_key(client_tee.get_public_key())
verifier.set_tee_public_key(tee_db_proxy.get_public_key())
client.set_personal_tee_public_key(client_tee.get_public_key())

def handle_verifier(result_queue):
    verifier.start(host, verifier_port, other_verifier_port, result_queue)
    
def handle_tee(result_queue):
    tee_db_proxy.start(host, tee_port, host, other_verifier_port, result_queue)
    
def handle_client(query, result_queue):
    result = client.start(host, client_tee_port, query)
    result_queue.put(result)
    
def handle_client_tee(result_queue):
    client_tee.start(host, client_tee_port, host, tee_port, host, verifier_port, result_queue)
    
csv_file = "results_subtime.csv"

query = generate_json_from_lists(["method", "route", "username", "password", "params"], ["GET", "is_bp_above_mean", "external1", "password", {"patient_id": "111111111111111111111111"}])
with open(csv_file, mode="a", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "User ID", "Category", "Elapsed Time (seconds)"])
    
csv_file_total = "results.csv"
with open(csv_file_total, mode="a", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "User ID", "Result", "Elapsed Time (seconds)"])
result_queue = queue.Queue() 
verifier_queue = queue.Queue()  
tee_queue = queue.Queue()
client_queue = queue.Queue() 
for i in range(100):
    verifier_thread = threading.Thread(target=handle_verifier, daemon=True, args=(verifier_queue,))
    tee_thread = threading.Thread(target=handle_tee, daemon=True, args=(tee_queue,))
    client_thread = threading.Thread(target=handle_client, args=(query, result_queue), daemon=True)
    client_tee_thread = threading.Thread(target=handle_client_tee, daemon=True, args=(client_queue,))
    verifier_thread.start()
    tee_thread.start()
    client_thread.start()
    client_tee_thread.start()
    verifier_thread.join()
    tee_thread.join()
    client_thread.join()
    client_tee_thread.join()
    
    verifier_results = []
    while not verifier_queue.empty():
        verifier_results.append(verifier_queue.get())
    tee_results = []
    while not tee_queue.empty():
        tee_results.append(tee_queue.get())
    client_results = []
    while not client_queue.empty():
        client_results.append(client_queue.get())
        
    with open(csv_file, mode="a", newline="") as file:
        writer = csv.writer(file)
        for item in verifier_results:
            writer.writerow([
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Current timestamp
                "external1",
                item[0],
                item[1]
            ])
        for item in tee_results:
            writer.writerow([
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Current timestamp
                "external1",
                item[0],
                item[1]
            ])
        for item in client_results:
            writer.writerow([
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Current timestamp
                "external1",
                item[0],
                item[1]
            ])
            
        
    
    client_result = result_queue.get()
    with open(csv_file_total, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Current timestamp
            "external1",
            client_result[0],
            client_result[1]
        ])
    print(f"Attempt {i + 1}/{100} for user external1: {client_result[0]} (Elapsed time: {client_result[1]} seconds)")
    time.sleep(2)
