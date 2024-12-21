import json
import threading
import time
import hashlib
import uuid
import base64
import sqlite3
from fastapi import FastAPI
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from typing import Dict, List

# Database file path
DATABASE_FILE = "keys.db"

def initialize_database():
    """Initialize the database and create the keys table if it doesn't exist."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            duration INTEGER,
            hwid TEXT
        )
        """)
        conn.commit()

def save_key_data(key_data):
    """Save the key data to the database."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        for key, data in key_data.items():
            cursor.execute("""
            INSERT INTO keys (key, duration, hwid)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET duration = excluded.duration, hwid = excluded.hwid
            """, (key, data['duration'], data['hwid']))
        conn.commit()

def load_key_data():
    """Load the key data from the database."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, duration, hwid FROM keys")
        data = cursor.fetchall()
        return {key: {'duration': duration, 'hwid': hwid} for key, duration, hwid in data}
    
initialize_database()
key_data = load_key_data()

sessions: List[Dict] = []

used_challenge_activators = []
activated_challenges = []
deactivated_challenges = []

HASH_SECRET = "zgC4S43KF33dLhjGDhUn5sBMKLkZTNRy"
ENC_SECRET = "4KKFCT6DtGEWhd9jqvrbKUAyHP3Mtfwk"
ENCRYPTION_KEY = hashlib.sha256(ENC_SECRET.encode()).digest()
IV = b'\x7f\xe6\x55\xf1\xfd\x1a\x48\xc3\x68\x6f\xd4\x9e\x57\x96\x6d\x49'

class EncryptedBase(BaseModel):
    data: str
    data2: dict

class CHBase(BaseModel):
    data: str

app = FastAPI()

# encryption
def encrypt_file_data(data: bytes) -> str:
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(IV))
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(ciphertext).decode('utf-8')

def encrypt_data(data: dict) -> str:
    plaintext = str(data).encode('utf-8')
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(IV))
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_data(encrypted_data: str) -> dict:
    ciphertext = base64.b64decode(encrypted_data)
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(IV))
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    return json.loads(plaintext.decode('utf-8'))

def generate_response_hash(challenge: str, key: str) -> str:
    if (challenge in deactivated_challenges or not challenge in activated_challenges):
        return False
    activated_challenges.remove(challenge)
    deactivated_challenges.append(challenge)

    combined = f"{challenge}{key}{HASH_SECRET}"
    return hashlib.sha256(combined.encode()).hexdigest().upper()

def verify_hash(request) -> bool:
    expected_hash = generate_response_hash(request['ch'], request['key'] + request['hwid'] + request['rng'])
    if request['rh'] != expected_hash:
        return False
    return True

def verify_hash_with_session(request) -> bool:
    expected_hash = generate_response_hash(request['ch'], request['key'] + request['session'] + request['hwid'] + request['rng'])
    if request['rh'] != expected_hash:
        return False
    return True

# run every 15 mins to clear unused sessions
def update_sessions():
    current_time = time.time()
    sessions[:] = [session for session in sessions if session['last_refresh'] >= current_time - 900] # delete sess after 15 mins

# run every 1h to reset possible challenges
def clear_used_challenges():
    deactivated_challenges.clear()
    activated_challenges.clear()

# run every second to pull new key data into db
def update_key_data():
    global key_data
    key_data = load_key_data()

# wrapper to run the background functions
def run_periodically(interval, func):
    def wrapper():
        while True:
            func()
            time.sleep(interval)
    
    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()

run_periodically(600, update_sessions)
run_periodically(3600, clear_used_challenges)
run_periodically(1, update_key_data)

async def activate_ch(enc_base):
    try:
        base = decrypt_data(enc_base['data'])

        # check if request is valid
        rh = hashlib.sha256(base['ch'].encode()).hexdigest().upper()
        if (rh != base['rh'] or base['ch'] in used_challenge_activators):
            return False

        actual_ch = hashlib.sha256(rh.encode()).hexdigest().upper()

        # we try to activate an already activated challenge that hasnt been consumed yet or challenge has already been used
        if (actual_ch in deactivated_challenges or actual_ch in activated_challenges):
            return False

        used_challenge_activators.append(base['ch'])
        activated_challenges.append(actual_ch)
        return True

    except:
        return False

@app.post("/verify_key/")
async def verify_key(enc_key: EncryptedBase):
    try:
        if not await activate_ch(enc_key.data2):
            response = {"ch_taken": "challenge used up"}
            return {"data": encrypt_data(response)}

        request = decrypt_data(enc_key.data)

        if (verify_hash(request) == False):
            response = {"error": "invalid hash"}
            return {"data": encrypt_data(response)}

        key = request['key']
        if key in key_data:
            if not key_data[key]['hwid']:
                key_data[key]['hwid'] = request['hwid']
                save_key_data(key_data)

            if key_data[key]['hwid'] == request['hwid']:
                response = {"key": key}
            else:
                response = {"error": "hwid mismatch"}
        else:
            response = {"error": "invalid key"}

        return {"data": encrypt_data(response)}

    except:
        response = {"error": "unknown"}
        return {"data": encrypt_data(response)}
    
@app.post("/get_duration/")
async def get_duration(enc_key: EncryptedBase):
    try:
        if not await activate_ch(enc_key.data2):
            response = {"ch_taken": "challenge used up"}
            return {"data": encrypt_data(response)}

        request = decrypt_data(enc_key.data)

        if (verify_hash(request) == False):
            response = {"error": "invalid hash"}
            return {"data": encrypt_data(response)}

        key = request['key']
        if key in key_data:
            if key_data[key]['hwid'] != request['hwid']:
                response = {"error": "hwid mismatch"}
            else:
                response = {"duration": key_data[key]['duration']}
        else:
            response = {"error": "invalid key"}
        return {"data": encrypt_data(response)}

    except:
        response = {"error": "unknown"}
        return {"data": encrypt_data(response)}
    
@app.post("/key_time_remaining/")
async def get_time_remaining(enc_key: EncryptedBase):
    try:
        if not await activate_ch(enc_key.data2):
            response = {"ch_taken": "challenge used up"}
            return {"data": encrypt_data(response)}

        request = decrypt_data(enc_key.data)

        if (verify_hash(request) == False):
            response = {"error": "invalid hash"}
            return {"data": encrypt_data(response)}

        key = request['key']
        if key in key_data:
            if key_data[key]['hwid'] != request['hwid']:
                response = {"error": "hwid mismatch"}
            else:
                response = {"time_remaining": max(key_data[key]['duration'] - time.time(), 0)}
        else:
            response = {"error": "invalid key"}
        return {"data": encrypt_data(response)}

    except:
        response = {"error": "unknown"}
        return {"data": encrypt_data(response)}

@app.post("/create_session/")
async def login(enc_base: EncryptedBase):
    try:
        if not await activate_ch(enc_base.data2):
            response = {"ch_taken": "challenge used up"}
            return {"data": encrypt_data(response)}

        request = decrypt_data(enc_base.data)

        if (verify_hash(request) == False):
            response = {"error": "invalid hash"}
            return {"data": encrypt_data(response)}

        session_id = str(uuid.uuid4())
        sessions.append({"session_id": session_id, "created": time.time(), "last_refresh": time.time(), "hwid": request['hwid'], "key": request['key']})
        response = {"session": session_id}
        return {"data": encrypt_data(response)}

    except:
        response = {"error": "unknown"}
        return {"data": encrypt_data(response)}

@app.post("/refresh_session/")
async def refresh_session(enc_session: EncryptedBase):
    try:
        if not await activate_ch(enc_session.data2):
            response = {"ch_taken": "challenge used up"}
            return {"data": encrypt_data(response)}

        request = decrypt_data(enc_session.data)

        if (verify_hash_with_session(request) == False):
            response = {"error": "invalid hash"}
            return {"data": encrypt_data(response)}

        for sess in sessions:
            if sess['session_id'] == request['session']:
                if (sess['hwid'] == request['hwid'] or sess['key'] == request['key']):
                    sess['last_refresh'] = time.time()
                    response = {"session": request['session']}
                    return {"data": encrypt_data(response)}

        response = {"error": "session not found"}
        return {"data": encrypt_data(response)}

    except:
        response = {"error": "unknown"}
        return {"data": encrypt_data(response)}

@app.post("/session_valid/")
async def session_valid(enc_session: EncryptedBase): 
    try:
        if not await activate_ch(enc_session.data2):
            response = {"ch_taken": "challenge used up"}
            return {"data": encrypt_data(response)}

        request = decrypt_data(enc_session.data)

        if (verify_hash_with_session(request) == False):
            response = {"error": "invalid hash"}
            return {"data": encrypt_data(response)}

        for sess in sessions:
            if sess['session_id'] == request['session']:
                if (sess['hwid'] == request['hwid'] or sess['key'] == request['key']):
                    response = {"session": request['session']}
                    return {"data": encrypt_data(response)}

        response = {"error": "session not found"}
        return {"data": encrypt_data(response)}

    except:
        response = {"error": "unknown"}
        return {"data": encrypt_data(response)}


@app.post("/download/")
async def download(enc_base: EncryptedBase):
    try:
        if not await activate_ch(enc_base.data2):
            response = {"ch_taken": "challenge used up"}
            return {"data": encrypt_data(response)}

        base = decrypt_data(enc_base.data)

        # check if everything so far is valid and setup correctly
        if (verify_hash_with_session(base) == False):
            response = {"error": "invalid hash"}
            return {"data": encrypt_data(response)}

        if not await session_valid(enc_base):
            response = {"error": "invalid session"}
            return {"data": encrypt_data(response)}

        if not await verify_key(enc_base):
            response = {"error": "invalid key"}
            return {"data": encrypt_data(response)}

        if await get_time_remaining(enc_base) == 0:
            response = {"error": "expired key"}
            return {"data": encrypt_data(response)}

        # load file
        in_file = open("rust_ext.exe", "rb")
        data = in_file.read()
        in_file.close()

        # write encrypted user data into file
        verification = ":".join([base['key'], base['session'], base['hwid']]).encode('utf-8')
        enc_verification = encrypt_file_data(verification).encode('utf-8')

        # encrypt file
        data = overwrite_data_at_position(data, enc_verification)
        enc_file = encrypt_file_data(data)
        
        # send encrypted file to client
        response = {"file": enc_file}
        return {"data": encrypt_data(response)}

    except:
        response = {"error": "unknown"}
        return {"data": encrypt_data(response)}

def overwrite_data_at_position(data: bytes, overwrite_data: bytes) -> bytes:
    position = len(data) - len(overwrite_data)
    return data[:position] + overwrite_data + data[position + len(overwrite_data):]