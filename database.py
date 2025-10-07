# database.py
import sqlite3
import os

DATABASE_URL = os.path.join(os.path.dirname(__file__), "evoting.db")

def get_db():
    conn = sqlite3.connect(DATABASE_URL, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS voters (
            voter_id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            name TEXT NOT NULL,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS votes (
            vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
            voter_id TEXT NOT NULL,
            encrypted_vote BLOB NOT NULL,
            receipt TEXT NOT NULL,
            cast_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (voter_id) REFERENCES voters (voter_id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS election_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            state TEXT NOT NULL DEFAULT 'VOTING_OPEN'
        )
    ''')
    
    # Initialize election_state if not exists
    cursor.execute('''
        INSERT OR IGNORE INTO election_state (id, state) 
        VALUES (1, 'VOTING_OPEN')
    ''')
    
    conn.commit()
    conn.close()