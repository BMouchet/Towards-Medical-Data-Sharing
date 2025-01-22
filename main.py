import copy
import datetime
import json
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
import random

client = MongoClient('localhost', 27017)

db_verif = client['pipelines']

approved_pipelines = db_verif['approved_pipelines']

db_client = client['data']
stored_pipelines = db_client['pipelines']
weight = db_client['bp']
# Drop the weight collection if it exists
weight.delete_many({})
# Populate the weight collection with random weights
for _ in range(100):  # Adjust the range as needed
    weight.insert_one({
        "_id": ObjectId(),
        # "weight": round(random.uniform(50.0, 120.0), 2)
        "bp": 80.0,
    })

pipeline = {
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

approved_pipelines.delete_many({})
approved_pipelines.insert_one(pipeline)
approved_pipelines.create_index("name", unique=True)
# Drop the stored pipelines collection if it exists
stored_pipelines.delete_many({})
# Populate the stored pipelines collection with random pipelines
stored_pipelines.insert_one(pipeline)
stored_pipelines.create_index("name", unique=True)

pipeline = approved_pipelines.find_one({"name": "is_bp_above_mean"})
print(pipeline)