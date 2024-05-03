from flask import Flask, request, render_template, jsonify, json
from main import *
from cvedb import *
from bson import ObjectId

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/', methods=['GET', 'POST'])
def results():
    if request.method == 'POST':
        tgtHost = request.form.get('ip')
        results = scan_all(tgtHost)
        result = scan_serviceport(tgtHost)
        return render_template("results.html", tgtHost=tgtHost, results=results, result=result)
    
@app.route('/vulner')
def vulner(): 
    return render_template("vulner.html")

@app.route('/search', methods=['POST'])
def search():
    data = request.get_json() 
    keyword = data.get('keyword', '')
    if keyword.strip() == '':  
        return jsonify([]) 
    else:
        search_results = search_data(keyword) 
        
        info_list = []
        
        for result in search_results:
            description_value = result['containers']['cna']['descriptions'][0]['value']
            cve_id = result['cveMetadata']['cveId']
            state = result['cveMetadata']['state']
            date_updated = result['cveMetadata']['dateUpdated']
            
            info_list.append({'description_value': description_value, 'cve_id': cve_id, 'state': state, 'date_updated': date_updated})
        
        return jsonify(info_list)

if __name__ == '__main__':
    app.run(port=8000, debug=True)