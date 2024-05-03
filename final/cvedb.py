from pymongo import MongoClient
import json
import os

client = MongoClient('mongodb://localhost:27017/')
db = client.cvedb
collection = db.cvelist
netcve_collection = db.networkcve

def insert_json_data(json_file):
    with open(json_file, 'r', encoding='UTF8') as file:
        data = json.load(file)
        if isinstance(data, dict):
            collection.insert_one(data)
        elif isinstance(data, list):  
            collection.insert_many(data) 
        else:
            print("Data format not supported for insertion.")

        
def process_all_files(directory):
    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.json'):
                file_path = os.path.join(root, filename)
                insert_json_data(file_path)

def search_data(keyword):
    query = {"containers.cna.descriptions.value": {"$regex": keyword, "$options": "i"}}
    results = collection.find(query)
    return list(results)

def transfer_network_documents():
    network_docs = collection.find({'containers.cna.metrics.cvssV3_1.attackVector': 'NETWORK'})
    
    netcve_collection.insert_many(network_docs)

    # original_collection.delete_many({'containers.cna.metrics.cvssV3_1.attackVector': 'NETWORK'})


# directory = 'C:\\Users\\zia20\\Downloads\\cvelistV5-main\\cvelistV5-main\\cves\\2021'
# process_all_files(directory)

# transfer_network_documents()

# search_results = search_data('mysql')
# print(search_results)