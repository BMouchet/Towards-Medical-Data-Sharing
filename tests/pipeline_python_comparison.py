import datetime
import json
import os
from bson import ObjectId
import dotenv
from pymongo import MongoClient
import random

dotenv.load_dotenv()
username = os.getenv('TEE_DB_USERNAME')
password = os.getenv('TEE_DB_PASSWORD')
uri = f'mongodb://{username}:{password}@localhost:27017/'
client = MongoClient(uri)

db = client['pipeline-python-metrics']

entries = 1000000

#initialize the database
users = db['user']
users.delete_many({})
patient_data = db['patient_data']
patient_data.delete_many({})
authorizations = db['authorizations']
authorizations.delete_many({})
pipelines = db['pipeline']
pipelines.delete_many({})
bps = db['bp']
bps.delete_many({})

doctor_id = ObjectId('000000000000000000000000')
doctor = {
        "_id": doctor_id,
        "username": "doctor1",
        "password": "password",
        "role": "doctor"
    }
users.insert_one(doctor)
patient_id = ObjectId('111111111111111111111111')
patient = {
    "_id": patient_id,
    "username": "patient1",
    "password": "password",
    "role": "patient"
}
users.insert_one(patient)
external_id = ObjectId( b'foo-bar-quux')
external = {
    "_id": external_id,
    "username": "external1",
    "password": "password",
    "role": "external"
}
users.insert_one(external)
access_control = {
        "_id": ObjectId('222222222222222222222222'),
        "users": [
            {
                "userId": doctor_id,
                "permissions": ["read"],
                "expiration": datetime.datetime(2026, 1, 1),
            },
            {
                "userId": external_id,
                "permissions": ["enclave"],
                "expiration": datetime.datetime(2026, 1, 1),
            }
        ]
    }
authorizations.insert_one(access_control)            

patient1_data = {
    "_id": ObjectId(),
    "patientId": patient_id,
    "accessControl": ObjectId(),
    "data": {
        "firstname": "John",
        "lastname": "Doe",
        "dob": "01/01/1970",
        "contactInfo": {
            "phone": "+1234567890",
            "email": "john.doe@example.com",
            "address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "Anystate",
                "zip": "12345",
                "country": "USA",
                "accessControl": ObjectId(),
            },
        },
        "metrics": {
            "height": 201.0,
            "weight": 49.0,
            "accessControl": ObjectId(),
            "sensitiveMetrics": {
                "bloodPressure": 181.0,
                
                "bloodType": "A+",
                "accessControl": ObjectId("222222222222222222222222"),
                "geneticData": {
                    "dnaSequence": "ACTGACTGACTG...",
                    "accessControl": ObjectId(),
                    "inheritedConditions": [
                        {
                            "condition": "Condition A",
                            "severity": "High",
                            "accessControl": ObjectId(),
                        },
                        {
                            "condition": "Condition B",
                            "severity": "Moderate",
                            "accessControl": ObjectId(),
                        },
                    ],
                },
            },
            "treatments": [
                {
                    "medication": "Medication A",
                    "posology": "3 pills/day",
                    "accessControl": ObjectId(),
                    "sideEffects": [
                        {"effect": "Nausea", "severity": "Mild"},
                        {"effect": "Headache", "severity": "Moderate"},
                    ],
                },
                {
                    "medication": "Medication B",
                    "posology": "1 pill/day",
                    "accessControl": ObjectId(),
                    "sideEffects": [
                        {"effect": "Dizziness", "severity": "Mild"},
                    ],
                },
            ],
            "labResults": {
                "recentTests": [
                    {
                        "testName": "Blood Test",
                        "date": "2024-01-01",
                        "results": {
                            "hemoglobin": 13.5,
                            "platelets": 250000,
                            "cholesterol": {
                                "ldl": 130,
                                "hdl": 50,
                            },
                        },
                        "accessControl": ObjectId(),
                    },
                    {
                        "testName": "X-ray",
                        "date": "2023-12-15",
                        "results": {
                            "description": "Fracture in the right wrist",
                            "severity": "Moderate",
                        },
                        "accessControl": ObjectId(),
                    },
                ],
                "accessControl": ObjectId(),
            },
        },
        "medicalHistory": {
            "pastIllnesses": [
                {"name": "Flu", "year": 2005, "treatment": "Rest and fluids"},
                {"name": "Appendicitis", "year": 2010, "treatment": "Surgery"},
            ],
            "surgeries": [
                {
                    "name": "Appendectomy",
                    "date": "2010-05-20",
                    "hospital": "General Hospital",
                    "accessControl": ObjectId(),
                },
            ],
            "accessControl": ObjectId(),
        },
        "insuranceDetails": {
            "provider": "HealthCare Inc.",
            "policyNumber": "HC123456789",
            "coverage": {
                "general": True,
                "specialized": {
                    "surgery": True,
                    "therapy": False,
                },
            },
            "accessControl": ObjectId(),
        },
    },
}
patient_data.insert_one(patient1_data)


for i in range(entries-1):
    user = {
        "_id": ObjectId(),
        "username": f"user_{i}",
        "password": "password",
        "role": "patient",
    }
    users.insert_one(user)
    authorization = {
        "_id": ObjectId(),
        "users": [
            {
                "userId": ObjectId(),
                "permissions": ["read", "write"],
                "expiration": datetime.datetime(2026, 1, 1),
            },
        ]
    }
    authorizations.insert_one(authorization)
    patient =     {
        "_id": ObjectId(),
        "patientId": str(patient_id),
        "accessControl": ObjectId(),
        "data": {
            "firstname": random.choice(["John", "Jane", "Alice", "Bob"]),
            "lastname": random.choice(["Doe", "Smith", "Brown", "Taylor"]),
            "dob": f"{random.randint(1, 28):02}/{random.randint(1, 12):02}/{random.randint(1940, 2000)}",
            "contactInfo": {
                "phone": f"+12345{random.randint(10000, 99999)}",
                "email": f"user{patient_id}@example.com",
                "address": {
                    "street": f"{random.randint(1, 999)} Main St",
                    "city": random.choice(["Anytown", "Somewhere", "Metroville"]),
                    "state": random.choice(["Anystate", "SomeState", "MetroState"]),
                    "zip": f"{random.randint(10000, 99999)}",
                    "country": "USA",
                    "accessControl": ObjectId(),
                },
            },
            "metrics": {
                "height": round(random.uniform(150.0, 210.0), 1),
                "weight": round(random.uniform(50.0, 120.0), 1),
                "accessControl": ObjectId(),
                "sensitiveMetrics": {
                    "bloodPressure":  round(random.uniform(90, 180), 1),
                    
                    "bloodType": random.choice(["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]),
                    "accessControl": ObjectId(),
                    "geneticData": {
                        "dnaSequence": "ACTG" * random.randint(10, 50),
                        "accessControl": ObjectId(),
                        "inheritedConditions": [
                            {
                                "condition": random.choice(["Condition A", "Condition B"]),
                                "severity": random.choice(["Low", "Moderate", "High"]),
                                "accessControl": ObjectId(),
                            }
                            for _ in range(random.randint(1, 3))
                        ],
                    },
                },
                "treatments": [
                    {
                        "medication": random.choice(["Medication A", "Medication B", "Medication C"]),
                        "posology": f"{random.randint(1, 3)} pills/day",
                        "accessControl": ObjectId(),
                        "sideEffects": [
                            {
                                "effect": random.choice(["Nausea", "Dizziness", "Headache"]),
                                "severity": random.choice(["Mild", "Moderate", "Severe"]),
                            }
                            for _ in range(random.randint(1, 2))
                        ],
                    }
                    for _ in range(random.randint(1, 3))
                ],
                "labResults": {
                    "recentTests": [
                        {
                            "testName": random.choice(["Blood Test", "X-ray", "MRI"]),
                            "date": f"{random.randint(2020, 2024)}-{random.randint(1, 12):02}-{random.randint(1, 28):02}",
                            "results": {
                                "description": "Normal" if random.random() > 0.2 else "Abnormal finding",
                                "cholesterol": {
                                    "ldl": round(random.uniform(80, 190), 1),
                                    "hdl": round(random.uniform(40, 60), 1),
                                },
                            },
                            "accessControl": ObjectId(),
                        }
                        for _ in range(random.randint(1, 3))
                    ],
                    "accessControl": ObjectId(),
                },
            },
            "medicalHistory": {
                "pastIllnesses": [
                    {"name": random.choice(["Flu", "Chickenpox", "Appendicitis"]), "year": random.randint(2000, 2020), "treatment": "Rest and fluids"}
                    for _ in range(random.randint(1, 3))
                ],
                "surgeries": [
                    {
                        "name": "Appendectomy",
                        "date": f"{random.randint(2000, 2020)}-05-20",
                        "hospital": "General Hospital",
                        "accessControl": ObjectId(),
                    }
                    for _ in range(random.randint(0, 2))
                ],
                "accessControl": ObjectId(),
            },
            "insuranceDetails": {
                "provider": random.choice(["HealthCare Inc.", "MediCare LLC"]),
                "policyNumber": f"HC{random.randint(100000, 999999)}",
                "coverage": {
                    "general": True,
                    "specialized": {
                        "surgery": random.choice([True, False]),
                        "therapy": random.choice([True, False]),
                    },
                },
                "accessControl": ObjectId(),
            },
        },
    }
    patient_data.insert_one(patient)
print("User data done initialized")    
pipelines_ = [
    {
        "_id": ObjectId(),
        "name": "get_bp",
        "pipeline": [
                {
                    "$match": {
                        "patientId": "$patient_id"
                    }
                },
                {
                    "$lookup": {
                        "from": "accessControls",
                        "localField": "data.metrics.sensitiveMetrics.accessControl",
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
                        "bp": {
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
                                        "then": "$data.metrics.sensitiveMetrics.bloodPressure",
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
            ]
        },
    {
    "name": "is_bp_above_mean",
    "pipeline": [
        {
            "$group": {
                "_id": None,
                "mean_bp": {"$avg": "$bp"}
            }
        },
        {
            "$project": {
                "_id": 0,  
                "mean_bp": 1,
                "is_above": {
                    "$cond": [
                        {"$gt": ["$input_bp", "$mean_bp"]},  
                        "1",
                        {"$cond": [
                            {"$lt": ["$input_bp", "$mean_bp"]},  
                            "-1",
                            "0"  
                        ]}
                    ]
                }
            }
        }
    ]
    }
]

pipelines.insert_many(pipelines_)

for i in range(entries-2):
    pipeline = {
        "_id": ObjectId(),
        "name": f"pipeline_{i}",
        "pipeline": [
            {
                "$group": {
                    "_id": None,
                    "mean_bp": {"$avg": "$bp"}
                }
            },
            {
                "$project": {
                    "_id": 0,  
                    "mean_bp": 1,
                    "is_above": {
                        "$cond": [
                            {"$gt": ["$input_bp", "$mean_bp"]},  
                            "1",
                            {"$cond": [
                                {"$lt": ["$input_bp", "$mean_bp"]},  
                                "-1",
                                "0"  
                            ]}
                        ]
                    }
                }
            }
        ]
    }
    pipelines.insert_one(pipeline)
    
pipelines.create_index("name", unique=True)
print("Pipeline data initialized")
for i in range(entries):
    bp = {
        "_id": ObjectId(),
        "bp": random.uniform(90.0, 180.0)
    }
    bps.insert_one(bp)

print("Database initialized")

def get_pipeline(template_name, params):
    pipeline_template = pipelines.find_one({"name": template_name})["pipeline"]
    for param_name, param_value in params.items():
        params[param_name] = validate_param(param_name, param_value)

    def replace_placeholders(obj):
        if isinstance(obj, dict):
            return {key: replace_placeholders(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [replace_placeholders(item) for item in obj]
        elif isinstance(obj, str) and obj.startswith("$"):
            placeholder = obj[1:]  
            validated_value = params.get(placeholder, obj)
            return validated_value  
        return obj

    return replace_placeholders(pipeline_template)

def validate_param(param_name, param_value):
    if param_name in ["patient_id", "user_id", "access_control_id", "target_user_id"]:
        if not isinstance(param_value, ObjectId):
            try:
                param_value = ObjectId(param_value)
            except Exception as e:
                raise ValueError(f"Invalid value for {param_name}: {param_value}. Error: {e}")
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
                expiration_datetime = datetime.datetime.strptime(param_value, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                raise ValueError(f"Invalid expiration time format: {param_value}. Expected format is YYYY-MM-DD HH:MM:SS")
        elif isinstance(param_value, datetime.datetime):
            expiration_datetime = param_value
        else:
            raise ValueError(f"Invalid expiration time: {param_value}. It should be a datetime or a valid datetime string.")
        if expiration_datetime <= datetime.datetime.now():
            raise ValueError(f"Expiration time must be in the future: {param_value}")
        return expiration_datetime
    elif param_name in ["input_bp"]:
        if not isinstance(param_value, (int, float)):
            raise ValueError(f"Invalid parameter value for {param_name}: {param_value}")
        return param_value
    else:
        raise ValueError(f"Invalid parameter name: {param_name}")
    
    
# Testing the pipeline 

# authorization = authorizations.find_one({"_id": ObjectId('222222222222222222222222')})
# print(authorization)                                        

# lookup_stage = [
#     {"$match": {"patientId": patient_id}},
#     {"$lookup": {
#         "from": "authorizations",
#         "localField": "data.metrics.sensitiveMetrics.accessControl",
#         "foreignField": "_id",
#         "as": "metricsAccessControl"
#     }}
# ]
# data = list(patient_data.aggregate(lookup_stage))
# print(json.dumps(data, default=str, indent=4))
# get_bp = get_pipeline("get_bp", {"patient_id": patient_id, "user_id": patient_id})
# print(get_bp)
# data = list(patient_data.aggregate(get_bp))
# data = data[0]['bp']
# bp_mean_check = get_pipeline("is_bp_above_mean", {"input_bp": data})
# print(bp_mean_check)
# result = list(bps.aggregate(bp_mean_check))
# print(result)

# Testing non pipeline
# user_id = patient_id
# attestation = False

# patient_data_ = patient_data.find_one({"patientId": patient_id})
# if patient_id == user_id:
#     print(patient_data_["data"]["metrics"]["sensitiveMetrics"]["bloodPressure"])
# else:
#     bp_ac_id = patient_data_["data"]["metrics"]["sensitiveMetrics"]["accessControl"]
#     ac = authorizations.find_one({"_id": bp_ac_id}) 
#     users = ac["users"]
#     print(users)
#     user_access = next((user for user in users if user["userId"] == user_id), None)
#     if user_access and user_access["expiration"] > datetime.datetime.now():
#         if "read" in user_access["permissions"]:
#             print(patient_data_["data"]["metrics"]["sensitiveMetrics"]["bloodPressure"])
#         else:
#             if attestation and "enclave" in user_access["permissions"]:
#                 print(patient_data_["data"]["metrics"]["sensitiveMetrics"]["bloodPressure"])
#             else:
#                 print("Attestation required")
#     else:
#         print("No access")
