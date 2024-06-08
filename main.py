from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from decryption import decryptData, validateCmac, parseEncryptedData
from verification import verifyData
from datetime import datetime, timedelta
import hmac
import hashlib
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
from fastapi.responses import JSONResponse
import boto3
from botocore.exceptions import ClientError
from typing import Optional
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
import uuid
from database import Base, engine, Client, updateClientInDatabase, getClientFromDb, get_db
from sqlalchemy.orm import Session
from utils import get_secret


SECRET_KEY = get_secret("secretKey")["secretKey"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
secrets = get_secret("resultDecrypt")
AES_KEY = bytes.fromhex(secrets['AES_KEY'])
HMAC_SECRET_KEY = base64.b64decode(secrets['HMAC_SECRET_KEY'])
API_VERSION = "/v1"
print(API_VERSION + "test")
app = FastAPI(
    title="Cryptag API",
    description="API documentation for Cryptag",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,  # Disable ReDoc
    openapi_url="/openapi.json"
)

# Models
class TagData(BaseModel):
    encryptedData: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

class Registration(BaseModel):
    user_id: int

class TokenRequest(BaseModel):
    client_id: str
    client_secret: str

# Password context for hashing passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password flow
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Helper functions
def verify_password(plain_secrete, db_secrete):
    return plain_secrete == db_secrete

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(clientId: str):
    getClientFromDb()
    return {"username":"Shubham", "hashed_password": "agbcjgsfdd=kkjhhsg"}

def authenticate_user(clientId: str, clientSecrete: str):
    client = getClientFromDb(clientId)
    if not client:
        return False
    if not verify_password(clientSecrete, client["client_secret"]):
        return False
    return client

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Routes
@app.post(API_VERSION + "/register")
async def register(registration: Registration):
    client_id = str(uuid.uuid4())
    client_secret = str(uuid.uuid4())
    new_client = updateClientInDatabase(clientId=client_id, clientSecret=client_secret, userId=registration.user_id)
    return {
        "client_id": client_id,
        "client_secret": client_secret
    }

@app.post(API_VERSION + "/token", response_model=Token)
async def login_for_access_token(request: TokenRequest):
    user = authenticate_user(request.client_id, request.client_secret)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect client_id or client_secret",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["client_id"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

def encrypt_aes(data, key):
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()

async def get_current_client(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        client_id: str = payload.get("sub")
        if client_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        client = db.query(Client).filter(Client.client_id == client_id).first()
        if client is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return client
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post(API_VERSION + "/read_tag")
async def read_tag(tagdata: TagData, current_client: Client = Depends(get_current_client)):
    try:
        encryptedData = tagdata.encryptedData
        piccData, encFileData, cmac = parseEncryptedData(encryptedData)
        response = decryptData(piccData, encFileData, cmac)
        if "error" in response:
            return response
        cmacStatus = response["cmac_status"] == "MAC is Correct"
        verifyRes = verifyData(response['uid'], response['sdm_read_cnt'], response["decrypted_encfiledata"], cmacStatus)
        if verifyRes["score"] >= 12:
            status = "Original"
        else:
            status = "Fake"
        current_time = datetime.now()
        retResponse = {
            "isBlacklisted": verifyRes["isBlacklisted"],
            "product": response["decrypted_encfiledata"],
            "result": status,
            "salt": current_time.strftime('%Y%m%d%H%M%S'),
            "timestamp": current_time.strftime('%Y-%m-%d %H:%M:%S')
        }
        hmac_value = hmac.new(HMAC_SECRET_KEY, f"{retResponse['result']}{retResponse['salt']}".encode(), hashlib.sha256).hexdigest()
        retResponse["HMAC"] = hmac_value
        response_json = json.dumps(retResponse).encode()
        encrypted_response = encrypt_aes(response_json, AES_KEY)
        return JSONResponse(content={"encryptedResult": encrypted_response})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8000)
