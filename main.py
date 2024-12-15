import copy
import datetime
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
import dotenv

# Load environment variables
dotenv.load_dotenv()

# Connect to MongoDB
username = os.getenv('TEE_DB_USERNAME')
password = os.getenv('TEE_DB_PASSWORD')
uri = f'mongodb://{username}:{password}@localhost:27017/'
client = MongoClient(uri)

db = client['medical-data']

# Example users
doctor = ObjectId()
patient = ObjectId()
external = ObjectId()
users = [
    {
        "_id": doctor,
        "username": "doctor1",
        "password": "password", 
        "role": "doctor"
    },
    {
        "_id": patient,
        "username": "patient1",
        "password": "password", 
        "role": "patient"
    },
    {
        "_id": external,
        "username": "external1",
        "password": "password",
        "role": "external"
    }
]

# Insert users
db.users.delete_many({})  # Clear existing users
db.users.insert_many(users)

# Example patients
patients = [
    {
        "_id": ObjectId(),
        "patientId": patient,
        "data": {
            "firstname": "John",
            "lastname": "Doe",
            "dob": "01/01/1970",
            "metrics": {
                "height": 170,
                "weight": 80,
                "bloodPressure": "130/85",
                "bloodType": "A+",
                "accessControl": [
                    {
                        "_id": ObjectId(),
                        "userId": doctor,
                        "permissions": ["read", "write"],
                        "expiration": datetime.datetime(2026, 1, 1),
                    },
                ],
            },
            "treatments": [
                {
                    "medication": "Medication A",
                    "posology": "3 pills/day",
                    "accessControl": [
                        {
                            "_id": ObjectId(),
                            "userId": doctor,
                            "permissions": ["read", "write"],
                            "expiration":  datetime.datetime(2026, 1, 1),
                        }
                    ],
                },
                {
                    "medication": "Medication B",
                    "posology": "1 pill/day",
                    "accessControl": [],
                },
            ],
            "accessControl": [
                {                
                    "_id": ObjectId(),        
                    "userId": doctor,
                    "permissions": ["read", "write"],
                    "expiration":  datetime.datetime(2026, 1, 1),
                },
                {
                    "_id": ObjectId(),
                    "userId": external,
                    "permissions": ["read"],
                    "expiration":  datetime.datetime(2026, 1, 1),
                }
            ],
        },
    },
]

# Insert patients
db.patients.delete_many({})  # Clear existing patients
db.patients.insert_many(patients)

print("Database populated with example users and patients.")



def get_pipeline(template_name, params):
    pipeline_template = copy.deepcopy(pipelines[template_name])
    
    for param_name, param_value in params.items():
        params[param_name] = validate_param(param_name, param_value)

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

def validate_param(param_name, param_value):
    print(f"Validating {param_name}: {param_value}")
    if param_name in ["patient_id", "user_id"]:
        if not isinstance(param_value, ObjectId):
            raise ValueError(f"Invalid value for {param_name}: {param_value}")
        return param_value
    elif param_name == "access_type":
        if param_value not in ["read", "write"]:
            raise ValueError(f"Invalid access type: {param_value}")
        return param_value
    elif param_name == "expiration":
        if isinstance(param_value, str):
            try:
                # Assuming the datetime format is "YYYY-MM-DD HH:MM:SS"
                expiration_datetime = datetime.datetime.strptime(param_value, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                raise ValueError(f"Invalid expiration time format: {param_value}. Expected format is YYYY-MM-DD HH:MM:SS")
        elif isinstance(param_value, datetime):
            expiration_datetime = param_value
        else:
            raise ValueError(f"Invalid expiration time: {param_value}. It should be a datetime or a valid datetime string.")
        
        # Optionally, compare expiration to current time to check if it's in the future
        if expiration_datetime <= datetime.now():
            raise ValueError(f"Expiration time must be in the future: {param_value}")
        
        # Return the expiration datetime object
        return expiration_datetime
    else:
        raise ValueError(f"Invalid parameter name: {param_name}")

def authenticate_user(username, password):
    user = db.users.find_one({"username": username, "password": password})
    if user:
        return user["_id"]
    else:
        raise ValueError("Invalid username or password")
    
doctor = authenticate_user("patient1", "password")
patient = db.users.find_one({"username": "patient1"})["_id"]
# Example query
# Define the parameters for the query

# Example query
# Define the parameters for the query
params = {
    "patient_id": patient,
    "user_id": doctor,
}

pipelines = {
    "get_height": [
        {"$match": {"patientId": "$patient_id"}}, 
        {
            "$project": {
                "height": {
                    "$cond": {
                        "if": {
                            "$or": [
                                {"$eq": ["$patientId", "$user_id"]},
                                {
                                    "$gt": [
                                        {
                                            "$size": {
                                                "$filter": {
                                                    "input": "$data.metrics.accessControl",
                                                    "as": "access",
                                                    "cond": {
                                                        "$and": [
                                                            {"$eq": ["$$access.userId", "$user_id"]},
                                                            {"$in": ["read", "$$access.permissions"]},
                                                            {
                                                                "$or": [
                                                                    {"$eq": ["$$access.expiration", None]},
                                                                    {"$gt": ["$$access.expiration", "$$NOW"]}
                                                                ]
                                                            },
                                                        ]
                                                    },
                                                }
                                            }
                                        },
                                        0,
                                    ]
                                },
                            ]
                        },
                        "then": "$data.metrics.height",
                        "else": None,
                    }
                },
                "_id": 0,
            }
        },
    ],
}

# Get the dynamically built pipeline
pipeline = get_pipeline("get_height", params)
print(pipeline)

# Execute the pipeline
result = db.patients.aggregate(pipeline)
print(list(result))