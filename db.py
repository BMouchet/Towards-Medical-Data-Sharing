from pymongo import MongoClient
from patient import Patient

class DB:
    def __init__(self):
        self.client = MongoClient('localhost', 27017)
        self.db = self.client['mydb']
        self.collection = self.db['mycollection']

    def insert_patient(self, patient):
        self.collection.insert_one(patient.to_document())
        print("Patient document inserted successfully.")

    def get_patient_data(self, patient_id, doctor_id):
        document = self.collection.find_one({"patient_id": patient_id})
        
        if not document:
            return "Patient not found."
        
        patient = Patient.from_document(document)
        
        result = {"public_info": patient.public_info}
        
        if doctor_id in patient.authorized_doctors:
            result["confidential_data"] = patient.confidential_data
        else:
            result["confidential_data"] = "Access Denied"
        
        return result

    def update_authorized_doctors(self, patient_id, doctor_id, action_doctor_id, add=True):
        if not self.is_admin(action_doctor_id):
            return "Access Denied: Only admins can modify authorized doctors."
        
        update_action = {"$addToSet": {"authorized_doctors": doctor_id}} if add else {"$pull": {"authorized_doctors": doctor_id}}
        result = self.collection.update_one({"patient_id": patient_id}, update_action)
        
        if result.modified_count:
            return "Authorized doctors list updated successfully."
        else:
            return "No changes made or patient not found."
    
    @staticmethod
    def is_admin(doctor_id):
        return doctor_id == "admin_doctor"
    
