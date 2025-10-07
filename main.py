import base64
import secrets
import json
import os
import sqlite3
import atexit
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse, RedirectResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from fastapi.middleware.cors import CORSMiddleware
from contextlib import contextmanager
import datetime

# --- Database Setup ---
DB_PATH = "evoting.db"

def init_database():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Voters table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS voters (
            voter_id TEXT PRIMARY KEY,
            public_key_pem TEXT NOT NULL,
            name TEXT NOT NULL,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Votes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voter_id TEXT NOT NULL,
            encrypted_vote BLOB NOT NULL,
            receipt TEXT NOT NULL UNIQUE,
            cast_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (voter_id) REFERENCES voters (voter_id)
        )
    ''')
    
    # Election state table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS election_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            state TEXT NOT NULL DEFAULT 'VOTING_OPEN',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Initialize election state if not exists
    cursor.execute('''
        INSERT OR IGNORE INTO election_state (id, state) 
        VALUES (1, 'VOTING_OPEN')
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    try:
        yield conn
    finally:
        conn.close()

# Initialize database on startup
init_database()

# --- WebSocket Connection Manager (for live updates) ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

# --- App Setup ---
app = FastAPI(
    title="Secure E-Voting System Backend",
    description="A secure, encrypted electronic voting system with real-time results",
    version="1.0.0"
)
security = HTTPBasic()

# CORS configuration - allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# This makes the 'static' folder available to the browser
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- Database Helper Functions ---
def get_election_state():
    """Get current election state from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT state FROM election_state WHERE id = 1")
        result = cursor.fetchone()
        return result['state'] if result else 'VOTING_OPEN'

def set_election_state(state: str):
    """Set election state in database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE election_state SET state = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
            (state,)
        )
        conn.commit()

def is_voter_registered(voter_id: str) -> bool:
    """Check if voter is already registered"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM voters WHERE voter_id = ?", (voter_id,))
        return cursor.fetchone() is not None

def register_voter_db(voter_id: str, public_key_pem: str, name: str):
    """Register a new voter in database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO voters (voter_id, public_key_pem, name) VALUES (?, ?, ?)",
            (voter_id, public_key_pem, name)
        )
        conn.commit()

def get_voter_public_key(voter_id: str) -> str:
    """Get voter's public key from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT public_key_pem FROM voters WHERE voter_id = ?", (voter_id,))
        result = cursor.fetchone()
        return result['public_key_pem'] if result else None

def has_voter_voted(voter_id: str) -> bool:
    """Check if voter has already cast a vote"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM votes WHERE voter_id = ?", (voter_id,))
        return cursor.fetchone() is not None

def record_vote(voter_id: str, encrypted_vote: bytes, receipt: str):
    """Record a vote in the database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO votes (voter_id, encrypted_vote, receipt) VALUES (?, ?, ?)",
            (voter_id, encrypted_vote, receipt)
        )
        conn.commit()

def get_all_receipts_db():
    """Get all vote receipts from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT receipt FROM votes ORDER BY cast_at")
        return [row['receipt'] for row in cursor.fetchall()]

def get_all_votes():
    """Get all encrypted votes from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_vote FROM votes")
        return [row['encrypted_vote'] for row in cursor.fetchall()]

def get_voter_stats():
    """Get voter statistics from database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Total registered voters
        cursor.execute("SELECT COUNT(*) as count FROM voters")
        total_registered = cursor.fetchone()['count']
        
        # Total votes cast
        cursor.execute("SELECT COUNT(DISTINCT voter_id) as count FROM votes")
        total_votes_cast = cursor.fetchone()['count']
        
        # Total receipts
        cursor.execute("SELECT COUNT(*) as count FROM votes")
        receipts_issued = cursor.fetchone()['count']
        
        return {
            "total_registered": total_registered,
            "total_votes_cast": total_votes_cast,
            "receipts_issued": receipts_issued
        }

def clear_election_data():
    """Clear all election data (for reset)"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM votes")
        cursor.execute("DELETE FROM voters")
        cursor.execute("UPDATE election_state SET state = 'VOTING_OPEN', updated_at = CURRENT_TIMESTAMP WHERE id = 1")
        conn.commit()

# --- Cryptography: Generate Keys for the Election Authority ---
print("🔐 Generating Election Authority key pair...")
ea_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ea_public_key_pem = ea_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')
print("✅ Election Authority setup complete.")

# --- Core Tallying Function ---
def _calculate_tally() -> dict:
    print("\n--- 📊 TALLYING ELECTION RESULTS ---")
    results = {}
    encrypted_votes = get_all_votes()
    
    if not encrypted_votes:
        return {"message": "The ballot box is empty."}
    
    for encrypted_vote in encrypted_votes:
        try:
            decrypted_vote = ea_private_key.decrypt(
                encrypted_vote,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).decode('utf-8')
            choice = decrypted_vote.replace("VOTE FOR ", "").strip()
            results[choice] = results.get(choice, 0) + 1
        except Exception as e:
            print(f"Decryption failed for a ballot: {e}")
            results["unaccounted_ballots"] = results.get("unaccounted_ballots", 0) + 1
    
    print("Final results:", results)
    return results

# --- Admin Authentication ---
def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, "admin")
    correct_password = secrets.compare_digest(credentials.password, "password123")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# --- Pydantic Models for Data Validation ---
class VoterRegistration(BaseModel):
    voter_id: str
    public_key_pem: str
    name: str

class CastVote(BaseModel):
    voter_id: str
    encrypted_vote_b64: str
    signature_b64: str

# --- API Endpoints ---

@app.get("/", response_class=FileResponse, tags=["Frontend"])
async def read_vote_page():
    return FileResponse('static/vote.html')

@app.get("/results", response_class=FileResponse, tags=["Frontend"])
async def read_results_page():
    return FileResponse('static/results.html')

@app.get("/admin", response_class=FileResponse, tags=["Admin Frontend"])
async def read_admin_page(username: str = Depends(get_current_user)):
    """Admin page with authentication required"""
    return FileResponse('static/admin.html')

@app.get("/election/key", tags=["Election"])
def get_election_authority_public_key():
    """Get the Election Authority public key for vote encryption"""
    return {"ea_public_key_pem": ea_public_key_pem}

@app.get("/election/status", tags=["Election"])
def get_election_status():
    """Get current election status"""
    stats = get_voter_stats()
    return {
        "election_state": get_election_state(),
        "total_registered": stats["total_registered"],
        "total_votes_cast": stats["total_votes_cast"],
        "receipts_issued": stats["receipts_issued"]
    }

@app.post("/voter/register", status_code=status.HTTP_201_CREATED, tags=["Voter"])
def register_voter(voter: VoterRegistration):
    """Register a new voter with their public key"""
    if get_election_state() == "VOTING_CLOSED":
        raise HTTPException(status_code=403, detail="Election is closed.")
    
    if is_voter_registered(voter.voter_id):
        raise HTTPException(status_code=400, detail="Voter ID already registered.")
    
    register_voter_db(voter.voter_id, voter.public_key_pem, voter.name)
    print(f"✅ Registered voter: {voter.name} ({voter.voter_id})")
    return {"message": f"Voter '{voter.name}' registered successfully."}

@app.post("/vote/cast", tags=["Voter"])
def cast_and_verify_vote(vote: CastVote):
    """Cast and verify a vote with digital signature"""
    if get_election_state() == "VOTING_CLOSED":
        raise HTTPException(status_code=403, detail="Election is closed.")
    
    if not is_voter_registered(vote.voter_id):
        raise HTTPException(status_code=404, detail="Voter not found. Please register first.")
    
    if has_voter_voted(vote.voter_id):
        raise HTTPException(status_code=403, detail="You have already voted.")

    try:
        voter_public_key_pem = get_voter_public_key(vote.voter_id)
        if not voter_public_key_pem:
            raise HTTPException(status_code=404, detail="Voter public key not found.")
            
        voter_public_key = serialization.load_pem_public_key(voter_public_key_pem.encode('utf-8'))
        voter_public_key.verify(
            base64.b64decode(vote.signature_b64),
            base64.b64decode(vote.encrypted_vote_b64),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception as e:
        print(f"❌ Signature verification failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid digital signature.")

    receipt = f"vrs-{secrets.token_hex(3)}-{secrets.token_hex(3)}"
    encrypted_vote_bytes = base64.b64decode(vote.encrypted_vote_b64)
    
    record_vote(vote.voter_id, encrypted_vote_bytes, receipt)
    print(f"✅ Vote cast by {vote.voter_id}, receipt: {receipt}")
    return {"message": "Vote cast successfully.", "receipt": receipt}

@app.get("/election/receipts", tags=["Election"])
def get_all_receipts():
    """Get all vote receipts (for verification)"""
    return {"receipts": get_all_receipts_db()}

@app.get("/election/results", tags=["Election"])
def get_public_results():
    """Get election results (only available when voting is closed)"""
    if get_election_state() != "VOTING_CLOSED":
        raise HTTPException(status_code=403, detail="Results are not available until the election is closed.")
    return _calculate_tally()

@app.websocket("/ws/results")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for live results updates"""
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- Admin Actions ---

@app.post("/election/close", tags=["Admin Actions"])
async def close_election(username: str = Depends(get_current_user)):
    """Close the election and broadcast results"""
    if get_election_state() == "VOTING_CLOSED":
        raise HTTPException(status_code=400, detail="Election is already closed.")
    
    set_election_state("VOTING_CLOSED")
    results = _calculate_tally()
    await manager.broadcast(json.dumps(results))
    print(f"🔒 Election closed by {username}")
    print(f"📊 Final results: {results}")
    return {"message": "Election is now closed and results have been broadcast.", "results": results}

@app.post("/election/open", tags=["Admin Actions"])
def open_election(username: str = Depends(get_current_user)):
    """Reset and open a new election"""
    clear_election_data()
    print(f"🔄 Election reset and opened by {username}")
    return {"message": "Election has been reset and opened."}

# Database backup endpoint
@app.get("/admin/backup", tags=["Admin Actions"])
def download_database_backup(username: str = Depends(get_current_user)):
    """Download database backup (admin only)"""
    if os.path.exists(DB_PATH):
        return FileResponse(DB_PATH, filename="evoting_backup.db", media_type='application/octet-stream')
    else:
        raise HTTPException(status_code=404, detail="Database file not found")

# Health check endpoint with database status
@app.get("/health", tags=["System"])
def health_check():
    """System health check"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    return {
        "status": "healthy", 
        "election_state": get_election_state(),
        "database": db_status,
        "timestamp": datetime.datetime.now().isoformat()
    }

# Root endpoint with API info
@app.get("/api")
def api_info():
    """API Information"""
    stats = get_voter_stats()
    return {
        "name": "Secure E-Voting System API",
        "version": "1.0.0",
        "database": "SQLite (Persistent)",
        "statistics": stats,
        "endpoints": {
            "voting": "/",
            "results": "/results",
            "admin": "/admin",
            "api_docs": "/docs"
        }
    }

# Cleanup on application shutdown
@atexit.register
def cleanup():
    print("🔄 Application shutting down...")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)