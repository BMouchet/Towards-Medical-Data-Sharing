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
doctor = ObjectId('000000000000000000000000')
patient = ObjectId('111111111111111111111111')
external = ObjectId('222222222222222222222222')
no_rights = ObjectId('777777777777777777777777')
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
    },
    {
        "_id": no_rights,
        "username": "no_rights",
        "password": "password",
        "role": "external"
    },
]

# Insert users
db.users.delete_many({})  # Clear existing users
db.users.insert_many(users)

access_controls = [
    {
        "_id": ObjectId('333333333333333333333333'),
        "users": [
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
        ]
    },
    {
        "_id": ObjectId('444444444444444444444444'),
        "users": [
            {
                "userId": doctor,
                "permissions": ["read", "write"],
                "expiration": datetime.datetime(2026, 1, 1),
            },
            {
                "userId": external,
                "permissions": ["enclave"],
                "expiration": datetime.datetime(2026, 1, 1),
            }
        ]
    },
    {
        "_id": ObjectId('555555555555555555555555'),
        "users": [
            {
                "userId": doctor,
                "permissions": ["read", "write"],
                "expiration": datetime.datetime(2026, 1, 1),
            },
        ]
    },
    {
        "_id": ObjectId('666666666666666666666666'),
        "users": []
    },
]

db.accessControls.delete_many({})  # Clear existing access controls
db.accessControls.insert_many(access_controls)

# Example patients
patients = [
    {
        "_id": ObjectId(),
        "patientId": patient,
        "accessControl": ObjectId('333333333333333333333333'),
        "data": {
            "firstname": "John",
            "lastname": "Doe",
            "dob": "01/01/1970",
            "metrics": {
                "height": 170,
                "weight": 150,
                "bloodPressure": "130/85",
                "bloodType": "A+",
                "accessControl": ObjectId('444444444444444444444444'),
                "treatments": [
                    {
                        "medication": "Medication A",
                        "posology": "3 pills/day",
                        "accessControl": ObjectId('555555555555555555555555'),
                    },
                    {
                        "medication": "Medication B",
                        "posology": "1 pill/day",
                        "accessControl": ObjectId('666666666666666666666666'),
                    },
                ],
            },
        },
    },
]

# Insert patients
db.patients.delete_many({})  # Clear existing patients
db.patients.insert_many(patients)

external_metrics = {
    "height_mean": 175,
}

# Insert external metrics
db.external_metrics.delete_many({})  # Clear existing external metrics
db.external_metrics.insert_one(external_metrics)

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
    elif param_name == "height_input":
        if not isinstance(param_value, (int, float)):
            raise ValueError(f"Invalid height input: {param_value}")
        return param_value
    elif param_name == "attestation":
        if not isinstance(param_value, bool):
            raise ValueError(f"Invalid attestation value: {param_value}")
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


pipelines = {
    "get_height": [
        {
            "$match": {
                "patientId": "$patient_id"
            }
        },
        {
            "$lookup": {
                "from": "accessControls",
                "localField": "data.metrics.accessControl",
                "foreignField": "_id",
                "as": "metricsAccessControl"
            }
        },
        {
            "$addFields": {
                "filteredUsers": {
                    "$filter": {
                        "input": "$metricsAccessControl.users",
                        "as": "userAccess",
                        "cond": {
                            "$and": [
                                {"$eq": ["$$userAccess.userId", "$user_id"]},
                                {"$in": ["enclave", "$$userAccess.permissions"]}
                            ]
                        }
                    }
                }
            }
        },
        {
            "$project": {
                "height": {
                    "$let": {
                        "vars": {
                            "enclaveMatch": {
                                "$filter": {
                                    "input": "$metricsAccessControl",
                                    "as": "control",
                                    "cond": {
                                        "$gt": [
                                            {
                                                "$size": {
                                                    "$filter": {
                                                        "input": "$$control.users",
                                                        "as": "userAccess",
                                                        "cond": {
                                                            "$and": [
                                                                {"$eq": ["$$userAccess.userId", "$user_id"]},
                                                                {
                                                                    "$or": [
                                                                        {
                                                                            "$and": [
                                                                                {"$in": ["enclave", "$$userAccess.permissions"]},
                                                                                {
                                                                                    "$or": [
                                                                                        {"$eq": ["$$userAccess.expiration", None]},
                                                                                        {"$gt": ["$$userAccess.expiration", "$$NOW"]}
                                                                                    ]
                                                                                }
                                                                            ]
                                                                        }
                                                                    ]
                                                                }
                                                            ]
                                                        }
                                                    }
                                                }
                                            },
                                            0
                                        ]
                                    }
                                }
                            },
                            "accessControlMatch": {
                                "$filter": {
                                    "input": "$metricsAccessControl",
                                    "as": "control",
                                    "cond": {
                                        "$gt": [
                                            {
                                                "$size": {
                                                    "$filter": {
                                                        "input": "$$control.users",
                                                        "as": "userAccess",
                                                        "cond": {
                                                            "$and": [
                                                                {"$eq": ["$$userAccess.userId", "$user_id"]},
                                                                {
                                                                    "$or": [
                                                                        {
                                                                            "$and": [
                                                                                {"$in": ["read", "$$userAccess.permissions"]},
                                                                                {
                                                                                    "$or": [
                                                                                        {"$eq": ["$$userAccess.expiration", None]},
                                                                                        {"$gt": ["$$userAccess.expiration", "$$NOW"]}
                                                                                    ]
                                                                                }
                                                                            ]
                                                                        },
                                                                        {
                                                                            "$and": [
                                                                                {"$in": ["enclave", "$$userAccess.permissions"]},
                                                                                {"$eq": ["$attestation", True]},
                                                                                {
                                                                                    "$or": [
                                                                                        {"$eq": ["$$userAccess.expiration", None]},
                                                                                        {"$gt": ["$$userAccess.expiration", "$$NOW"]}
                                                                                    ]
                                                                                }
                                                                            ]
                                                                        }
                                                                    ]
                                                                }
                                                            ]
                                                        }
                                                    }
                                                }
                                            },
                                            0
                                        ]
                                    }
                                }
                            }
                        },
                        "in": {
                            "$cond": {
                                "if": {
                                    "$or": [
                                        {"$eq": ["$patientId", "$user_id"]},
                                        {"$gt": [{"$size": "$$accessControlMatch"}, 0]}
                                    ]
                                },
                                "then": "$data.metrics.height",
                                "else": {
                                    "$cond": {
                                        "if": {
                                            "$and": [
                                                {"$eq": ["$attestation", False]},
                                                {"$gt": [{"$size": "$$enclaveMatch"}, 0]}
                                            ]
                                        },
                                        "then": "attestation required",
                                        "else": None
                                    }
                                }
                            }
                        }
                    }
                },
                "_id": 0
            }
        }
    ],

    "is_taller_than_mean": [
        {
            "$addFields": {
                "is_taller_than_mean": {
                    "$cond": {
                        "if": {"$gt": ["$height_input", "$height_mean"]},  # Compare height input with mean height
                        "then": True,
                        "else": False
                    }
                }
            }
        },
        {
            "$project": {
                "_id": 0,  # Exclude the `_id` field from the result
                "is_taller_than_mean": 1  # Include the `is_taller_than_mean` field in the result
            }
        }
    ],
}

params = {
    "patient_id": patient,
    "user_id": patient,
}

pipeline = get_pipeline("get_height", params)
result = db.patients.aggregate(pipeline)
print(list(result))

params = {
    "patient_id": patient,
    "user_id": external,
    "attestation": False,
}

pipeline = get_pipeline("get_height", params)
result = db.patients.aggregate(pipeline)
print(list(result))

params = {
    "patient_id": patient,
    "user_id": external,
    "attestation": True,
}

pipeline = get_pipeline("get_height", params)
result = db.patients.aggregate(pipeline)
print(list(result))

params = {
    "patient_id": patient,
    "user_id": no_rights,
    "attestation": False,
}

pipeline = get_pipeline("get_height", params)
result = db.patients.aggregate(pipeline)
print(list(result))

params = {
    "patient_id": patient,
    "user_id": no_rights,
    "attestation": True,
}

pipeline = get_pipeline("get_height", params)
result = db.patients.aggregate(pipeline)
print(list(result))

params = {
    "patient_id": patient,
    "user_id": doctor,
}

pipeline = get_pipeline("get_height", params)
result = db.patients.aggregate(pipeline)
print(list(result))
