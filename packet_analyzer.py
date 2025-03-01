import eventlet
eventlet.monkey_patch()

from scapy.all import sniff, IP, TCP, UDP
from database import db_manager
from datetime import datetime
from app import app

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Detección básica de escaneo de puertos
        if TCP in packet and packet[TCP].flags == 2:  # SYN flag
            log_event("Port Scan Attempt", src_ip, dst_ip, f"Port: {packet[TCP].dport}")
        
        # Detección básica de posible ataque DoS
        if TCP in packet and packet[TCP].flags == 0:  # NULL flags
            log_event("Possible DoS Attack", src_ip, dst_ip, "NULL flags detected")
        
        # Detección básica de posible inyección de paquetes
        if UDP in packet and packet[UDP].len > 1000:
            log_event("Possible Packet Injection", src_ip, dst_ip, f"Large UDP packet: {packet[UDP].len} bytes")

def log_event(event_type, src_ip, dst_ip, details):
    with app.app_context():
        db_manager.log_event(event_type, src_ip, dst_ip, details)
        print(f"Event logged: {event_type} from {src_ip} to {dst_ip}")

def start_monitoring(interface="eth0"):
    print(f"Starting packet capture on interface {interface}")
    sniff(iface=interface, prn=analyze_packet, store=0)