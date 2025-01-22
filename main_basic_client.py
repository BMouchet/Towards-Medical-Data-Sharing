import csv
import datetime
import queue
from bson import ObjectId
from basic_client import BasicClient
from tee_db_proxy import TEE_DB_Proxy
from verifier import Verifier
import threading
import time

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
client = BasicClient(ca_cert_file, tee_db_proxy.get_public_key(), verifier.get_public_key())
verifier.set_tee_public_key(tee_db_proxy.get_public_key())

def handle_verifier():
    verifier.start(host, verifier_port, other_verifier_port)
    
def handle_tee():
    tee_db_proxy.start(host, tee_port, host, other_verifier_port)

def handle_client(query, result_queue):
    result = client.start(host, tee_port, host, verifier_port, query)
    result_queue.put(result)
    
    
queries = [
    ["GET", "get_bp", "patient1", "password", {"patient_id": str(ObjectId('111111111111111111111111'))}],
    ["GET", "get_bp", "doctor1", "password", {"patient_id": str(ObjectId('111111111111111111111111'))}],
    ["GET", "get_bp", "external1", "password", {"patient_id": str(ObjectId('111111111111111111111111'))}]
]
filename = "results_100_basic.csv"
# Prepare the CSV file with a header row
with open(filename, mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "User ID", "Client Result", "Elapsed Time (seconds)"])

tries = 100
result_queue = queue.Queue()  
for i in range(tries):
    for query in queries:
        verifier_thread = threading.Thread(target=handle_verifier)
        tee_thread = threading.Thread(target=handle_tee)
        client_thread = threading.Thread(target=handle_client, args=(query, result_queue))

        start_time = time.time()

        verifier_thread.start()
        tee_thread.start()
        client_thread.start()

        client_thread.join()
        end_time = time.time()
        result = result_queue.get()
        try:
            with open(filename, mode="a", newline="") as file:
                writer = csv.writer(file)
                writer.writerow([
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Current timestamp
                    query[2],
                    result,
                    end_time - start_time  # Elapsed time in seconds
                ])
        except Exception as e:
            print(f"Error writing to CSV file: {e}")
        print(f"Attempt {i + 1}/{tries} for user {query[2]}: {result} (Elapsed time: {end_time - start_time} seconds)")
        time.sleep(1)