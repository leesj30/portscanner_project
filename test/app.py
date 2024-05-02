from flask import Flask, request, render_template, jsonify, json
from main import scan_all

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/', methods=['GET', 'POST'])
def results():
    if request.method == 'POST':
        tgtHost = request.form.get('ip')
        results = scan_all(tgtHost)
        return render_template("results.html", tgtHost=tgtHost, results=results)
    
@app.route('/vulner')
def vulner(): 
    return render_template("vulner.html")


if __name__ == '__main__':
    app.run(port=8000, debug=True)