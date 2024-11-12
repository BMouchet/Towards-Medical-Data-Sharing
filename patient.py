
class Patient:
    def __init__(self, patient_id, public_info, confidential_data=None, authorized_doctors=None):
        self.patient_id = patient_id
        self.public_info = public_info
        self.confidential_data = confidential_data or {}
        self.authorized_doctors = authorized_doctors or []

    def to_document(self):
        """Converts the patient instance to a dictionary for MongoDB storage."""
        return {
            "patient_id": self.patient_id,
            "public_info": self.public_info,
            "confidential_data": self.confidential_data,
            "authorized_doctors": self.authorized_doctors
        }
    
    @classmethod
    def from_document(cls, document):
        """Creates a Patient instance from a MongoDB document."""
        return cls(
            patient_id=document["patient_id"],
            public_info=document["public_info"],
            confidential_data=document.get("confidential_data", {}),
            authorized_doctors=document.get("authorized_doctors", [])
        )