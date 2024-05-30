from sqlalchemy import create_engine, Column, String, Integer, Boolean, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.inspection import inspect
from fastapi import HTTPException
DATABASE_URL = "postgresql://postgres:postgres*123@localhost:5432/postgres"

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

class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String, unique=True, index=True)
    client_secret = Column(String, unique=True, index=True)
    user_id = Column(Integer)

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


def updateTagTable(data: dict):
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
                if key == 'blacklistvalue':
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
