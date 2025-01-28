import copy
import datetime
import json
import random
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
import dotenv

dotenv.load_dotenv()

username = os.getenv('TEE_DB_USERNAME')
password = os.getenv('TEE_DB_PASSWORD')
uri = f'mongodb://{username}:{password}@localhost:27017/'
client = MongoClient(uri)

db = client["test_dataset"]
pipeline_collection = db["pipelines"]
user_collection = db["users"]
patient_collection = db["patients"]
accesse_collection = db["accessControls"]
bp_collection = db["bps"]

entries = 1000000

pipelines = [
    {
    "_id": ObjectId(),
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
    ],
    },
    {
        "_id": ObjectId(),
        "name": "get_height",
        "pipeline": [
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
            ]
        },
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
]

pipeline_collection.delete_many({})
pipeline_collection.insert_many(pipelines)

for i in range(entries):
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
    pipeline_collection.insert_one(pipeline)

print("Populated pipelines")

doctor = ObjectId('000000000000000000000000')
patient = ObjectId('111111111111111111111111')
external = ObjectId('222222222222222222222222')

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
]

user_collection.delete_many({})
user_collection.insert_many(users)

for i in range(entries):
    user = {
        "_id": ObjectId(),
        "username": f"user_{i}",
        "password": "password",
        "role": "patient"
    }
    user_collection.insert_one(user)
    
print("Populated users")

patients = [
    {
        "_id": ObjectId(),
        "patientId": patient,
        "accessControl": ObjectId('333333333333333333333333'),
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
                "height": 170,
                "weight": 150,
                "accessControl": ObjectId('333333333333333333333333'),
                "sensitiveMetrics": {
                    "bloodPressure": 100.0,
                    "bloodType": "A+",
                    "accessControl": ObjectId('444444444444444444444444'),
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
]

patient_collection.delete_many({})  
patient_collection.insert_many(patients)
accesse_collection.delete_many({})
ac = {
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
}
accesse_collection.insert_one(ac)   

for i in range(entries):
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
    accesse_collection.insert_one(authorization)
    patient_data =     {
        "_id": ObjectId(),
        "patientId": str(patient),
        "accessControl": ObjectId(),
        "data": {
            "firstname": random.choice(["John", "Jane", "Alice", "Bob"]),
            "lastname": random.choice(["Doe", "Smith", "Brown", "Taylor"]),
            "dob": f"{random.randint(1, 28):02}/{random.randint(1, 12):02}/{random.randint(1940, 2000)}",
            "contactInfo": {
                "phone": f"+12345{random.randint(10000, 99999)}",
                "email": f"user{patient}@example.com",
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
    patient_collection.insert_one(patient_data)
print("Patient data done initialized")    

bp_collection.delete_many({})
for i in range(entries):
    bp = {
        "_id": ObjectId(),
        "patient": ObjectId(),
        "bp": round(random.uniform(90, 180), 1),
        "attestation": random.choice([True, False]),
        "user_id": ObjectId(),
    }
    bp_collection.insert_one(bp)
    
print("Populated blood pressure data")