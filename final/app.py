from flask import Flask, request, render_template, jsonify, json
from final import main
from pymongo import MongoClient
from final.cvedb import *

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/', methods=['GET', 'POST'])
def results():
    if request.method == 'POST':
        tgtHost = request.form.get('ip')
        results = main(tgtHost)
        return render_template("results.html", tgtHost=tgtHost, results=results)
    
@app.route('/vulner')
def vulner(): 
    return render_template("vulner.html")

@app.route('/search', methods=['POST'])
def search():
    keyword = request.json['keyword']
    results = search_data(keyword)
    html_results = '<ul>'
    for result in results:
        html_results += '<li>' + json.dumps(result) + '</li>'
    html_results += '</ul>'
    return jsonify(html_results)

if __name__ == '__main__':
    app.run(port=8000, debug=True)