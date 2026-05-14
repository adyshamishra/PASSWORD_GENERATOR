import sqlite3

def initialize_db():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS master_key 
                      (id INTEGER PRIMARY KEY, salt BLOB, hashed_key BLOB)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords 
                      (id INTEGER PRIMARY KEY, service TEXT, username TEXT, encrypted_password BLOB)''')
    conn.commit()
    conn.close()

def master_exists():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM master_key")
    res = cursor.fetchone()
    conn.close()
    return res is not None

def get_master_credentials():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT salt, hashed_key FROM master_key WHERE id=1")
    res = cursor.fetchone()
    conn.close()
    return res

def save_password(service, username, encrypted_pwd):
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (service, username, encrypted_password) VALUES (?, ?, ?)", 
                   (service, username, encrypted_pwd))
    conn.commit()
    conn.close()

def fetch_all_passwords():
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, username, encrypted_password FROM passwords")
    rows = cursor.fetchall()
    conn.close()
    return rows