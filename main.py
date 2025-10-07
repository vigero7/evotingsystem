import base64
import secrets
import json
import os
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse, RedirectResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from fastapi.middleware.cors import CORSMiddleware

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

# --- In-Memory "Database" ---
db = {
    "election_state": "VOTING_OPEN",
    "registered_voters": {},
    "votes_cast": set(),
    "ballot_box": [],
    "vote_receipts": []
}

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
    if not db["ballot_box"]:
        return {"message": "The ballot box is empty."}
    for encrypted_vote in db["ballot_box"]:
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
    return {
        "election_state": db["election_state"],
        "total_registered": len(db["registered_voters"]),
        "total_votes_cast": len(db["votes_cast"]),
        "receipts_issued": len(db["vote_receipts"])
    }

@app.post("/voter/register", status_code=status.HTTP_201_CREATED, tags=["Voter"])
def register_voter(voter: VoterRegistration):
    """Register a new voter with their public key"""
    if db["election_state"] == "VOTING_CLOSED":
        raise HTTPException(status_code=403, detail="Election is closed.")
    if voter.voter_id in db["registered_voters"]:
        raise HTTPException(status_code=400, detail="Voter ID already registered.")
    
    db["registered_voters"][voter.voter_id] = {"key": voter.public_key_pem, "name": voter.name}
    print(f"✅ Registered voter: {voter.name} ({voter.voter_id})")
    return {"message": f"Voter '{voter.name}' registered successfully."}

@app.post("/vote/cast", tags=["Voter"])
def cast_and_verify_vote(vote: CastVote):
    """Cast and verify a vote with digital signature"""
    if db["election_state"] == "VOTING_CLOSED":
        raise HTTPException(status_code=403, detail="Election is closed.")
    if vote.voter_id not in db["registered_voters"]:
        raise HTTPException(status_code=404, detail="Voter not found. Please register first.")
    if vote.voter_id in db["votes_cast"]:
        raise HTTPException(status_code=403, detail="You have already voted.")

    try:
        voter_public_key = serialization.load_pem_public_key(db["registered_voters"][vote.voter_id]["key"].encode('utf-8'))
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
    db["vote_receipts"].append(receipt)
    db["ballot_box"].append(base64.b64decode(vote.encrypted_vote_b64))
    db["votes_cast"].add(vote.voter_id)
    print(f"✅ Vote cast by {vote.voter_id}, receipt: {receipt}")
    return {"message": "Vote cast successfully.", "receipt": receipt}

@app.get("/election/receipts", tags=["Election"])
def get_all_receipts():
    """Get all vote receipts (for verification)"""
    return {"receipts": db["vote_receipts"]}

@app.get("/election/results", tags=["Election"])
def get_public_results():
    """Get election results (only available when voting is closed)"""
    if db["election_state"] != "VOTING_CLOSED":
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
    if db["election_state"] == "VOTING_CLOSED":
        raise HTTPException(status_code=400, detail="Election is already closed.")
    
    db["election_state"] = "VOTING_CLOSED"
    results = _calculate_tally()
    await manager.broadcast(json.dumps(results))
    print(f"🔒 Election closed by {username}")
    print(f"📊 Final results: {results}")
    return {"message": "Election is now closed and results have been broadcast.", "results": results}

@app.post("/election/open", tags=["Admin Actions"])
def open_election(username: str = Depends(get_current_user)):
    """Reset and open a new election"""
    global db
    db = {
        "election_state": "VOTING_OPEN",
        "registered_voters": {},
        "votes_cast": set(),
        "ballot_box": [],
        "vote_receipts": []
    }
    print(f"🔄 Election reset and opened by {username}")
    return {"message": "Election has been reset and opened."}

# Health check endpoint
@app.get("/health", tags=["System"])
def health_check():
    """System health check"""
    return {"status": "healthy", "election_state": db["election_state"]}

# Root endpoint with API info
@app.get("/api")
def api_info():
    """API Information"""
    return {
        "name": "Secure E-Voting System API",
        "version": "1.0.0",
        "endpoints": {
            "voting": "/",
            "results": "/results",
            "admin": "/admin",
            "api_docs": "/docs"
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)