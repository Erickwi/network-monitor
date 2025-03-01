import eventlet
eventlet.monkey_patch()

from scapy.all import sniff, IP, TCP, UDP
from database import db_manager
from datetime import datetime
from flask import Flask, jsonify, send_file, request
import queue
import threading
import csv
import json
import time
import os

app = Flask(__name__)
capture_running = False
event_queue = queue.Queue()
capture_thread = None

def set_capture_running(value):
    global capture_running
    capture_running = value

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Detección básica de escaneo de puertos
        if TCP in packet and packet[TCP].flags == 2:  # SYN flag
            event_queue.put(("Port Scan Attempt", src_ip, dst_ip, f"Port: {packet[TCP].dport}"))
        
        # Detección básica de posible ataque DoS
        if TCP in packet and packet[TCP].flags == 0:  # NULL flags
            event_queue.put(("Possible DoS Attack", src_ip, dst_ip, "NULL flags detected"))
        
        # Detección básica de posible inyección de paquetes
        if UDP in packet and packet[UDP].len > 1000:
            event_queue.put(("Possible Packet Injection", src_ip, dst_ip, f"Large UDP packet: {packet[UDP].len} bytes"))

def log_event(event_type, src_ip, dst_ip, details):
    with app.app_context():
        db_manager.log_event(event_type, src_ip, dst_ip, details)
        print(f"Event logged: {event_type} from {src_ip} to {dst_ip}")

def event_processor():
    while True:
        event_type, src_ip, dst_ip, details = event_queue.get()
        log_event(event_type, src_ip, dst_ip, details)
        event_queue.task_done()

def start_monitoring(interface="eth0"):
    print(f"Starting packet capture on interface {interface}")
    threading.Thread(target=event_processor, daemon=True).start()
    sniff(iface=interface, prn=analyze_packet, store=0)

def generate_report(report_type):
    events = db_manager.get_recent_events()
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    
    if report_type == 'csv':
        # Generate CSV report
        csv_filename = f'report_{timestamp}.csv'
        with open(csv_filename, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'event_type', 'src_ip', 'dst_ip', 'details']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                writer.writerow({
                    'timestamp': event[1],
                    'event_type': event[2],
                    'src_ip': event[3],
                    'dst_ip': event[4],
                    'details': event[5]
                })
        return csv_filename
    
    elif report_type == 'json':
        # Generate JSON report
        json_filename = f'report_{timestamp}.json'
        with open(json_filename, 'w') as jsonfile:
            json.dump([{
                'timestamp': event[1],
                'event_type': event[2],
                'src_ip': event[3],
                'dst_ip': event[4],
                'details': event[5]
            } for event in events], jsonfile, indent=4)
        return json_filename

@app.route('/start_capture', methods=['GET'])
def start_capture():
    global capture_thread
    if capture_thread is None or not capture_thread.is_alive():
        set_capture_running(True)
        capture_thread = threading.Thread(target=start_monitoring)
        capture_thread.start()
        return jsonify({"status": "Capture started"})
    else:
        return jsonify({"status": "Capture already running"})

@app.route('/stop_capture', methods=['GET'])
def stop_capture():
    set_capture_running(False)
    return jsonify({"status": "Capture stopped"})

@app.route('/generate_report', methods=['GET'])
def generate_report_endpoint():
    report_type = request.args.get('type', 'csv')
    filename = generate_report(report_type)
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(port=5001, debug=True)