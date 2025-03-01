import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, Response, jsonify, request
from database import db_manager
import time
import json
import requests

app = Flask(__name__)

@app.route('/')
def index():
    events = db_manager.get_recent_events()
    return render_template('index.html', events=events)

@app.route('/events')
def sse():
    return Response(event_stream(), mimetype='text/event-stream')

def event_stream():
    while True:
        time.sleep(1)
        events = db_manager.get_recent_events()
        yield f"data: {json.dumps(events)}\n\n"

@app.route('/start_capture')
def start_capture():
    response = requests.get('http://localhost:5001/start_capture')
    return jsonify(response.json())

@app.route('/generate_report')
def generate_report():
    report_type = request.args.get('type', 'csv')
    response = requests.get(f'http://localhost:5001/generate_report?type={report_type}')
    return jsonify(response.json())

@app.route('/stop_capture')
def stop_capture():
    response = requests.get('http://localhost:5001/stop_capture')
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(debug=True, threaded=True)