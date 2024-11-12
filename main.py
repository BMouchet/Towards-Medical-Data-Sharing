import threading
import time
from patient import Patient
from server_implementation import Server
from hello_world_client import HelloWorldClient
from db import DB
def run_server():
    server = Server()
    try:
        server.start_server()
    except KeyboardInterrupt:
        server.stop()

def run_client(name):
    client = HelloWorldClient(name=name)
    client.start()

if __name__ == "__main__":
    # Start the server in a separate thread
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()

    # Give the server a moment to start
    time.sleep(1)

    # Start two clients
    client1_thread = threading.Thread(target=run_client, args=("Alice",))
    client2_thread = threading.Thread(target=run_client, args=("Bob",))

    client1_thread.start()
    client2_thread.start()

    # Wait for clients to finish
    client1_thread.join()
    client2_thread.join()

    print("Both clients have finished communicating with the server.")

    db = DB()
    new_patient = Patient(
        patient_id=12345,
        public_info={
            "name": "John Doe",
            "age": 45,
            "height": "180",
        },
        confidential_data={
            "condition": "Hypertension",
            "prescriptions": ["Drug A", "Drug B"],
            "doctor_notes": "Patient should monitor blood pressure daily."
        },
        authorized_doctors=["doctor_id_1"] 
    )
    new_patient2 = Patient(
        patient_id=54321,
        public_info={
            "name": "Jane Smith",
            "age": 32,
            "height": "165",
        },
        confidential_data={
            "condition": "Diabetes",
            "prescriptions": ["Insulin"],
            "doctor_notes": "Patient should avoid sugary foods."
        },
        authorized_doctors=["doctor_id_2"]  
    )

    db.insert_patient(new_patient)
    db.insert_patient(new_patient2)

    print("Data for authorized doctor:")
    print(db.get_patient_data(12345, "doctor_id_1"))

    # Retrieve patient data with unauthorized access
    print("Data for unauthorized doctor:")
    print(db.get_patient_data(12345, "doctor_id_2"))

