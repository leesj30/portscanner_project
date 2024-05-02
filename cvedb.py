from pymongo import MongoClient
import json
import os

client = MongoClient('mongodb://localhost:27017/')
db = client.cvedb
collection = db.cvelist
netcve_collection = db.networkcve

# JSON 파일 로드 및 MongoDB에 삽입
def insert_json_data(json_file):
    with open(json_file, 'r', encoding='UTF8') as file:
        data = json.load(file)
        if isinstance(data, dict):  # 데이터가 사전 형태인 경우
            collection.insert_one(data)
        elif isinstance(data, list):  # 데이터가 리스트 형태인 경우
            collection.insert_many(data)  # 리스트 내의 모든 사전을 삽입
        else:
            print("Data format not supported for insertion.")

        
# 모든 하위 디렉토리를 포함하여 JSON 파일 처리
def process_all_files(directory):
    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.json'):
                file_path = os.path.join(root, filename)
                insert_json_data(file_path)

def search_data(keyword):
    # "descriptions.value" 필드에서 키워드에 대한 부분 일치 검색을 수행
    query = {"containers.cna.descriptions.value": {"$regex": keyword, "$options": "i"}}
    results = collection.find(query)
    return list(results)

# 'attackVector'가 'NETWORK'인 문서 이동
def transfer_network_documents():
    # 'NETWORK' 문서 조회
    network_docs = collection.find({'containers.cna.metrics.cvssV3_1.attackVector': 'NETWORK'})
    
    # 새 컬렉션에 문서 삽입
    netcve_collection.insert_many(network_docs)

    # 필요한 경우, 기존 컬렉션에서 해당 문서를 삭제
    # original_collection.delete_many({'containers.cna.metrics.cvssV3_1.attackVector': 'NETWORK'})


#directory = 'C:\\Users\\siriu\\Downloads\\cvelistV5-main\\cvelistV5-main\\cves\\2020'
#process_all_files(directory)

#transfer_network_documents()

search_results = search_data('mysql')
print(search_results)