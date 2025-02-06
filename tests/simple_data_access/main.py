import csv
import datetime
import queue
import threading
import time
from client import Client
from tee_db_proxy import TEE_DB_Proxy
from verifier import Verifier

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
tee_db_proxy = TEE_DB_Proxy(ca_cert_file, server_cert_file, server_key_file)
client = Client(ca_cert_file, tee_db_proxy.get_public_key(), verifier.get_public_key())

verifier.set_tee_public_key(tee_db_proxy.get_public_key())

def handle_verifier(result_queue):
    verifier.start(host, verifier_port, result_queue)
    
def handle_tee(result_queue):
    tee_db_proxy.start(host, tee_port, result_queue)

def handle_client(query, result_queue):
    result = client.start(host, tee_port, host, verifier_port, query)
    result_queue.put(result)
    
users = ["patient1", "doctor1"]
csv_file = "results.csv"
csv_subtimes_file = "results_subtimes.csv"

# Prepare the CSV file with a header row
with open(csv_file, mode="a", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "User ID", "Client Result", "Elapsed Time (seconds)"])

with open(csv_subtimes_file, mode="a", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "User ID", "Category", "Elapsed Time (seconds)"])


for i in range(100):
    for user in users:
        query = generate_json_from_lists(["method", "route", "username", "password", "params"], ["GET", "get_bp", user, "password", {"patient_id": "111111111111111111111111"}])
        result_queue = queue.Queue()  
        verifier_results = queue.Queue()
        proxy_results = queue.Queue()   
        verifier_thread = threading.Thread(target=handle_verifier, args=(verifier_results,))
        tee_thread = threading.Thread(target=handle_tee, args=(proxy_results,))
        client_thread = threading.Thread(target=handle_client, args=(query, result_queue))

        verifier_thread.start()
        tee_thread.start()
        client_thread.start()

        client_thread.join()
        verifier_thread.join()
        tee_thread.join()
        client_result = result_queue.get()
        verifier_content = []
        while not verifier_results.empty():
            verifier_content.append(verifier_results.get())

        proxy_content = []
        while not proxy_results.empty():
            proxy_content.append(proxy_results.get())
            
        with open(csv_subtimes_file, mode="a", newline="") as file:
            writer = csv.writer(file)
            for item in verifier_content:
                writer.writerow([
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Current timestamp
                    user,
                    item[0],
                    item[1]
                ])
            for item in proxy_content:
                writer.writerow([
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Current timestamp
                    user,
                    item[0],
                    item[1]
                ])

        with open(csv_file, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Current timestamp
                user,
                client_result[0],
                client_result[1]
            ])
        print(f"Attempt {i + 1}/{100} for user {user}: {client_result[0]} (Elapsed time: {client_result[1]} seconds)")
        time.sleep(1)