from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from decryption import decryptData, validateCmac, parseEncryptedData, kdf, derive_key
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
from database import Base, engine, Client, updateClientInDatabase, getClientFromDb, get_db, register_client_in_database,get_clients_from_database,add_tag_in_database, get_tags_from_database,device_log_in_database, delete_client_from_database, update_tag_in_database,get_client_api_keys_secrets_from_database,delete_client_api_keys_from_database,update_client_in_database,add_admin_user_in_database,update_admin_user_in_database,delete_admin_user_from_database, AdminUser, get_admin_user_from_database,get_device_logs_from_database
from sqlalchemy.orm import Session
from utils import get_secret
from fastapi.middleware.cors import CORSMiddleware
from typing import List

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
    docs_url="/",
    redoc_url=None,  # Disable ReDoc
    openapi_url="/openapi.json"
)

# Configure CORS
origins = [
    "http://localhost:5173",  # Your local development server
    "http://localhost:5174",  # Your local development server
    "http://127.0.0.1:5174",  # Localhost with IP
    "http://127.0.0.1:5173",  # Localhost with IP
    # Add other origins if needed, such as your production frontend URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allow specified origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)


# Models
class TagData(BaseModel):
    encryptedData: str
    systemID: str
    systemIP: str
    systemVersion: str
    deviceType: str
    timestamp: str

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

class Tag(BaseModel):
    filedata: str
    readcnt: int
    uid: str

class ClientDataBase(BaseModel):
    id: int
    username: str
    #companyname: str

    class Config:
        from_attributes = True

class TagModel(BaseModel):
    clientid : int
    #username : str
    uid: str
    batchno: str
    tagstatus:str
    tagactivateddatetime: str
    sdmreadcnt: int
    lastscandatetime: str
    fraud : int
    blacklistvalue : bool
    client: Optional[ClientDataBase] = None
    class Config:
        from_attributes = True


class KeysModel(BaseModel):
    key0 : str
    key1 : str
    key2 : str
    key3 : str

class ClientData(BaseModel):
    username: str
    password: str
    email: str
    phone: str
    companyname: str
    companyregtype: str
    industrytype: str

class ClientModel(ClientData):
    id: int
    accountstatus : str
    registrationdate: str

    class Config:
        from_attributes = True
class ClientApiModel(ClientModel):
    apikey: str
    secret: str

    class Config:
        from_attributes = True

class AdminUserModel(BaseModel):
    id: int
    email: str
    first_name: str
    last_name: str
    password: str
    profile: str
    permission: str

    class Config:
        from_attributes = True

class DeviceLogModel(BaseModel):
    id : int
    systemip: str
    systemid: str
    systemversion: str
    devicetype: str
    timestamp: str
    uid:str

    class Config:
        from_attributes = True



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


def extract_serial_parts(serial):
        print("serial is :",serial)
        return {
            'tag_edition': serial[7:9],
            'kv': serial[9:11],
            'product_serial': serial[-4:]
        }
@app.post(API_VERSION + "/read-tag")
async def read_tag(tagdata: TagData, current_client: Client = Depends(get_current_client)):
    try:
        print(tagdata.encryptedData)
        serial_parts = extract_serial_parts(tagdata.encryptedData[:21])
        encryptedData = tagdata.encryptedData[21:]
        print(serial_parts['tag_edition'])
        print(serial_parts['kv'])
        print(serial_parts['product_serial'])
        #encryptedData = tagdata.encryptedData
        piccData, encFileData, cmac = parseEncryptedData(encryptedData)
        salt = serial_parts['tag_edition'] + serial_parts['kv'] + serial_parts['product_serial']
        response = decryptData(serial_parts['kv'], salt,piccData, encFileData, cmac)
        if "error" in response:
            return response
        cmacStatus = response["cmac_status"] == "MAC is Correct"
        verifyRes = verifyData(serial_parts['kv'], salt, response['uid'], response['sdm_read_cnt'], response["decrypted_encfiledata"], cmacStatus)
        device_log_in_database(tagdata,response['uid'])
        print("Final score is : ",verifyRes)
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

@app.post(API_VERSION + "/register-client")
async def register_client(clientdata: ClientData):
    try:
        return register_client_in_database(clientdata)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
 
@app.get(API_VERSION + "/manage-clients", response_model=List[ClientModel])
async def get_clients():
    print("got get request for clients")
    try:
        clients = get_clients_from_database()
        return clients
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get(API_VERSION + "/taginfo", response_model=List[TagModel])
async def get_tag_information():
    print("got get request for taginfo")
    try:
        tags = get_tags_from_database()
        return tags
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post(API_VERSION + "/add-tag")
async def add_tag(tagdata: List[Tag]):
    print("In add_tag",tagdata)
    try:
        return add_tag_in_database(tagdata)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get(API_VERSION + "/generate-keys/{uid}", response_model=KeysModel)
async def generate_keys(uid: str):
    print("get request for /generate-keys")
    serial_parts = extract_serial_parts(uid)
    #encryptedData = tagdata.encryptedData[21:]
    print(serial_parts['tag_edition'])
    print(serial_parts['kv'])
    print(serial_parts['product_serial'])
    tag_edition = serial_parts['tag_edition']
    kv = serial_parts['kv']
    product_serial = serial_parts['product_serial']       
    salt = tag_edition + kv + product_serial
    derived_keys = [derive_key(kv,salt, index) for index in range(5)]
    return {'key0' : derived_keys[0], 'key1' : derived_keys[1], 'key2' : derived_keys[2], 'key3' : derived_keys[3]}
    return kdf(uid)

@app.delete(API_VERSION + "/delete-client/{id}")
async def delete_client(id: int):
    print("delete request for id = ",id)
    try:
        return delete_client_from_database(id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.put(API_VERSION + "/update-tag/{id}")
async def update_tag(id: int, updated_tag: TagModel):
    print("update tag for id = ",id)
    try:
        return update_tag_in_database(id, updated_tag)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get(API_VERSION + "/client-api-keys", response_model=List[ClientApiModel])
async def get_client_api_key_secret():
    print("get request for /client-api-keys")
    return get_client_api_keys_secrets_from_database()


@app.delete(API_VERSION + "/client-api-keys/{id}")
async def delete_api_keys(id: int):
    print("delete keys for id = ",id)
    try:
        return delete_client_api_keys_from_database(id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.put(API_VERSION + "/manage-clients/{id}")
async def update_client(id : int, updatedClient : ClientModel):
    print("Update the client")
    try:
        clients =  update_client_in_database(id, updatedClient)
        return clients
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get(API_VERSION + "/admin-user", response_model=List[AdminUserModel])
async def get_admin_user():
    print("got post request to add the admin user")
    try:
       return get_admin_user_from_database()
    except ValueError as e:
       raise HTTPException(status_code=400, detail=str(e))

@app.get(API_VERSION + "/admin-user/{emailid}", response_model=List[AdminUserModel])
async def get_admin_user(emailid: str):
    print("got post request to add the admin user")
    try:
       return get_admin_user_from_database(emailid)
    except ValueError as e:
       raise HTTPException(status_code=400, detail=str(e))


@app.post(API_VERSION + "/admin-user")
async def add_admin_user(user : AdminUserModel):
    print("got post request to add the admin user")
    try:
       return add_admin_user_in_database(user)
    except ValueError as e:
       raise HTTPException(status_code=400, detail=str(e))



@app.put(API_VERSION + "/admin-user/{id}")
async def update_admin_user(id:int, admin_user: AdminUserModel):
    print("got post request to update the admin user")
    try:
       update_admin_user_in_database(id,admin_user)
    except ValueError as e:
       raise HTTPException(status_code=400, detail=str(e))

@app.delete(API_VERSION + "/admin-user/{id}")
async def delete_admin_user(id : int):
    print("got post request to delete the admin user")
    try:
       delete_admin_user_from_database(id)
    except ValueError as e:
       raise HTTPException(status_code=400, detail=str(e))

@app.get(API_VERSION + "/device-logs", response_model=List[DeviceLogModel])
async def get_device_logs():
    print("got get request for device logs")
    try:
       return get_device_logs_from_database()
    except ValueError as e:
       raise HTTPException(status_code=400, detail=str(e))




@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8000)
