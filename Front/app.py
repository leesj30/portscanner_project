from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/', methods=['GET', 'POST'])
def results():
    if request.method == 'POST':
        target_ip = request.form.get('ip')
        #results = sacn('ip')
        return render_template("results.html", target_ip=target_ip)
    
@app.route('/vulner')
def vulner():
    return render_template("vulner.html")

if __name__ == '__main__':
    app.run(port=8000, debug=True)