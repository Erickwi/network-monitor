import sqlite3
from datetime import datetime
import os

class DatabaseManager:
    def __init__(self, db_name='network_events.db'):
        self.db_name = db_name
        self.conn = None
        self.cursor = None

    def connect(self):
        # Crear la base de datos si no existe
        db_exists = os.path.exists(self.db_name)
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        
        if not db_exists:
            print(f"Base de datos '{self.db_name}' creada.")
        else:
            print(f"Conectado a la base de datos existente '{self.db_name}'.")

    def disconnect(self):
        if self.conn:
            self.conn.close()
            print("Desconectado de la base de datos.")

    def create_tables(self):
        self.connect()
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            details TEXT
        )
        ''')
        self.conn.commit()
        print("Tabla 'events' creada o verificada.")
        self.disconnect()

    def log_event(self, event_type, src_ip, dst_ip, details):
        self.connect()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute('''
        INSERT INTO events (timestamp, event_type, source_ip, destination_ip, details)
        VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, event_type, src_ip, dst_ip, details))
        self.conn.commit()
        print(f"Evento registrado: {event_type} desde {src_ip} a {dst_ip}")
        self.disconnect()

    def get_recent_events(self):
        self.connect()
        self.cursor.execute("SELECT * FROM events ORDER BY timestamp DESC")
        events = self.cursor.fetchall()
        self.disconnect()
        return events

# Crear una instancia de DatabaseManager y crear las tablas
db_manager = DatabaseManager()
db_manager.create_tables()

