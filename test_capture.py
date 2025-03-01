import pytest
import requests
from flask import Flask
from capture import app as capture_app, db_manager
from app import app as web_app

@pytest.fixture
def client():
    web_app.config['TESTING'] = True
    with web_app.test_client() as client:
        with web_app.app_context():
            yield client

def test_start_capture(client):
    response = client.get('/start_capture')
    assert response.status_code == 200
    assert response.json['status'] == 'Capture started'

def test_stop_capture(client):
    response = client.get('/stop_capture')
    assert response.status_code == 200
    assert response.json['status'] == 'Capture stopped'

def test_generate_report_json(client):
    response = client.get('/generate_report?type=json')
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/json'
    json_data = response.get_json()
    assert isinstance(json_data, list)

def test_event_logging():
    db_manager.connect()
    db_manager.log_event('Test Event', '192.168.1.1', '192.168.1.2', 'Test details')
    events = db_manager.get_recent_events()
    assert len(events) > 0
    assert events[0][2] == 'Test Event'
    assert events[0][3] == '192.168.1.1'
    assert events[0][4] == '192.168.1.2'
    assert events[0][5] == 'Test details'