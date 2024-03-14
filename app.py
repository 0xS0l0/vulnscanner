from flask import Flask, render_template, request
from scan import scan_website

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    vulnerabilities = scan_website(url)
    return render_template('result.html', url=url, vulnerabilities=vulnerabilities)

if __name__ == '__main__':
    app.run(debug=True)
