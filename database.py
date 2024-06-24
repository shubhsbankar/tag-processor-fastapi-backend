from sqlalchemy import create_engine, Column, String, Integer, Boolean, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.inspection import inspect
from fastapi import HTTPException
from datetime import datetime
#DATABASE_URL = "postgresql://postgres:postgres*123@localhost:5432/postgres"
DATABASE_URL = "postgresql://cryptagadmin:J7e2UqKsM1iHr3XQNAbC@tag-db.c9y6e0my4hua.ap-south-1.rds.amazonaws.com:5432/tag_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Define the Tag model
class Tag(Base):
    __tablename__ = "tag"
    uid = Column(String, primary_key=True, index=True)
    counter = Column(Integer)
    encryptedfiledata = Column(String)
    blacklistvalue = Column(Boolean)
    sdmreadcnt = Column(Integer)
    proccessedcnt = Column(Integer)

class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String, unique=True, index=True)
    client_secret = Column(String, unique=True, index=True)
    user_id = Column(Integer)

class ClientData(Base):
    __tablename__ = "clientdata"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    password = Column(String)
    companyname = Column(String)
    companyregtype = Column(String)
    industrytype = Column(String)
    email = Column(String, unique=True, index=True)
    phone = Column(String, unique=True, index=True)
    accountstatus = Column(String)
    registrationdate = Column(String)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def getTagDataFromPostgres(uid: str):
    print("database : uid ", uid)
    db = SessionLocal()
    try:
        tag = db.query(Tag).filter(Tag.uid == uid).first()
        if tag:
            return {column.key: getattr(tag, column.key) for column in inspect(tag).mapper.column_attrs}
        else:
            return None
    finally:
        db.close()

def getClientFromDb(clientId: str):
    print("database : clientId ", clientId)
    db = SessionLocal()
    try:
        client = db.query(Client).filter(Client.client_id == clientId).first()
        if client:
            return {column.key: getattr(client, column.key) for column in inspect(client).mapper.column_attrs}
        else:
            return None
    finally:
        db.close()


def updateTagTable(data: dict, keyTobeUpdated: str):
    db = SessionLocal()
    try:
        uid = data.get('uid')
        if not uid:
            raise ValueError("UID is required to update the tag")
        
        tag = db.query(Tag).filter(Tag.uid == uid).first()
        if not tag:
            raise ValueError(f"No tag found with UID: {uid}")
        
        for key, value in data.items():
            if hasattr(tag, key):
                if key == keyTobeUpdated:
                   setattr(tag, key, value)
        
        db.commit()
        #return tag_to_dict(tag)
    finally:
        db.close()

def updateClientInDatabase(clientId: str, clientSecret: str, userId: int):
    db1 = SessionLocal()
    try:
        client = db1.query(Client).filter(Client.user_id == userId).first()
        print(client)
        if client is not None:
            #raise ValueError(f"Already client is registered with client_id: {userId}")
            errorText = "Already client is registered with client_id: " + str(userId)
            raise HTTPException(status_code=400, detail=errorText)
        #return {"error" : errorText}
        
        # Create a new client instance
        new_client = Client(
            client_id=clientId,
            client_secret=clientSecret,
            user_id=userId
        )
        
        # Add the new client to the session
        db1.add(new_client)
        
        # Commit the transaction
        db1.commit()
        
        # Refresh the session to include the new client
        db1.refresh(new_client)
        
        # Return the newly created client
        return new_client
    except Exception as e:
        db1.rollback()
        raise e
    finally:
        db1.close()

def register_client_in_database(data):
    print(data)
    db = SessionLocal()
    try:
        #client = db.query(Client).filter(Client.user_id == userId).first()
        # Check if the email or phone already exists
        existing_client = db.query(ClientData).filter(
            (ClientData.email == data.email) | (ClientData.phone == data.phone)
        ).first()

        if existing_client:
            raise HTTPException(
                status_code=400,
                detail="A client with this email or phone number already exists."
            )
        db_client = ClientData(
          username=data.username,
          companyname=data.companyName,
          industrytype=data.industryType,
          email=data.email,
          phone=data.phone,
          companyregtype=data.companyRegType,
          password=data.password,
          accountstatus="Active",
          registrationdate=datetime.now().strftime("%d-%m-%Y")
        )
        db.add(db_client)
        db.commit()
        db.refresh(db_client)
        return db_client
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def get_clients_from_database():
    db = SessionLocal()
    try:
       clients = db.query(ClientData).offset(skip).limit(limit).all()
       if clients:
           raise HTTPException(
           status_code=400,
           detail='No client is register'
           )
       return clients
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

