import copy
import datetime
import json
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
        "accessControl": [                   
                        {
                            "userId": doctor,
                            "permissions": ["read", "write"],
                            "expiration": datetime.datetime(2026, 1, 1),
                        },
                        {
                            "userId": external,
                            "permissions": ["read"],
                            "expiration": datetime.datetime(2026, 1, 1),
                        }
                    ],
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
                            "userId": doctor,
                            "permissions": ["read", "write"],
                            "expiration": datetime.datetime(2027, 1, 1),
                        },
                    ],
            "treatments": [
                {
                    "medication": "Medication A",
                    "posology": "3 pills/day",
                    "accessControl":[                   
                        {
                            "userId": doctor,
                            "permissions": ["read", "write"],
                            "expiration": datetime.datetime(2026, 1, 1),
                        },
                    ],
            
                },
                {
                    "medication": "Medication B",
                    "posology": "1 pill/day",
                    "accessControl": [   
                        ],
                    
                },
            ],
            },
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
    if param_name in ["patient_id", "user_id", "access_control_id", "target_user_id"]:
        if not isinstance(param_value, ObjectId):
            raise ValueError(f"Invalid value for {param_name}: {param_value}")
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
            "is_heavier_than": [
        {"$match": {"patientId": "$patient_id"}}, 
        {
            "$project": {
                "is_heavier_than": {
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
                        "then": {
                            "$cond": {
                                "if": {"$gt": ["$data.metrics.weight", 100]},
                                "then": True,
                                "else": False
                            }
                        },
                        "else": None
                    }
                },
                "_id": 0,
            }
        },
    ],
    "add_authorization": [
        {
            "$match": {
                "patientId": "$user_id"  # Ensure the patient is performing the action
            }
        },
        {
            "$set": {
                "$access_control_path": {
                    "$map": {
                        "input": "$access_control_path",
                        "as": "accessControl",
                        "in": {
                            "$cond": {
                                "if": {
                                    "$eq": ["$$accessControl._id", "$access_control_id"]
                                },
                                "then": {
                                    "$mergeObjects": [
                                        "$$accessControl",
                                        {
                                            "users": {
                                                "$concatArrays": [
                                                    "$$accessControl.users",
                                                    [
                                                        {
                                                            "userId": "$target_user_id",
                                                            "permissions": "$access_type",
                                                            "expiration": "$expiration"
                                                        }
                                                    ]
                                                ]
                                            }
                                        }
                                    ]
                                },
                                "else": "$$accessControl"
                            }
                        }
                    }
                }
            }
        }
    ]
}
       
params = {
    "patient_id": patient,
    "user_id": external,
}
        
# Get the dynamically built pipeline
pipeline = get_pipeline("is_heavier_than", params)
print(pipeline)

# Execute the pipeline
result = db.patients.aggregate(pipeline)
print(list(result))

params = {
    "patient_id": patient,
    "access_control_path": "data.metrics",
    "user_id": patient,
    "target_user_id": external,
    "access_type": ["write"],
    "expiration": datetime.datetime(2026, 1, 1),
}
print("Old docu")
updated_document = db.patients.find_one({"patientId": patient})
print(json.dumps(updated_document, indent=4, default=str))
pipeline = get_pipeline("add_authorization", params)
print(pipeline)

result = db.patients.aggregate(pipeline)
updated_document = db.patients.find_one({"patientId": patient})

print("Updated document:")
print(json.dumps(updated_document, indent=4, default=str))
print(ObjectId(b'foo-bar-quux'))
params = {
    "patient_id": patient,
    "user_id": external,
}
        
# Get the dynamically built pipeline
pipeline = get_pipeline("is_heavier_than", params)
print(pipeline)

# Execute the pipeline
result = db.patients.aggregate(pipeline)
print(list(result))