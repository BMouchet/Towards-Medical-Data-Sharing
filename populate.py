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

pipelines = [
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


db.pipelines.delete_many({})
db.pipelines.insert_many(pipelines)
print("Pipelines created successfully")
db.pipelines.create_index("name", unique=True)
