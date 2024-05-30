from flask import Flask, render_template, request
from scan import scan_website
from requests.exceptions import ConnectionError
from flask import jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        url = request.form['url']
        results = scan_website(url)
        return render_template('result.html', results=results)
    except ConnectionError:
        error_message = "Failed to connect to the server. Please check the URL and try again."
        return jsonify({'error': error_message}), 500

if __name__ == '__main__':
    app.run(debug=True)
