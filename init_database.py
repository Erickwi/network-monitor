from database import DatabaseManager

def initialize_database():
    db = DatabaseManager()
    db.create_tables()
    
    # Mostrar la estructura de la base de datos
    db.connect()
    db.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = db.cursor.fetchall()
    
    print("\nEstructura de la base de datos:")
    for table in tables:
        print(f"\nTabla: {table[0]}")
        db.cursor.execute(f"PRAGMA table_info({table[0]})")
        columns = db.cursor.fetchall()
        for column in columns:
            print(f"  - {column[1]} ({column[2]})")
    
    db.disconnect()

if __name__ == "__main__":
    initialize_database()

