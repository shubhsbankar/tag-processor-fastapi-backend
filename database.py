from sqlalchemy import create_engine, Column, String, Integer, Boolean, select, ForeignKey, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship, mapped_column, Mapped
from sqlalchemy.inspection import inspect
from fastapi import HTTPException
from datetime import datetime
from sqlalchemy.orm import joinedload
#DATABASE_URL = "postgresql://postgres:postgres*123@localhost:5432/postgres"
DATABASE_URL = "postgresql://cryptagadmin:J7e2UqKsM1iHr3XQNAbC@tag-db.c9y6e0my4hua.ap-south-1.rds.amazonaws.com:5432/tag_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Define the Tag model
class Tag(Base):
    __tablename__ = "tag"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    uid = Column(String, primary_key=True, index=True)
    counter = Column(Integer)
    encryptedfiledata = Column(String)
    blacklistvalue = Column(Boolean)
    sdmreadcnt = Column(Integer)
    proccessedcnt = Column(Integer)
    tagactivateddatetime = Column(String)
    clientid = Column(Integer, ForeignKey('clientdata.id'), nullable=False)
    batchno = Column(String)
    tagstatus = Column(String)
    lastscandatetime = Column(String)
    fraud = Column(Integer)
    client = relationship("ClientData", back_populates="tags")

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
    apikey = Column(String)
    secret = Column(String)

class DeviceLog(Base):
    __tablename__ = "devicelog"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    systemip = Column(String)
    systemid = Column(String)
    systemversion = Column(String)
    devicetype = Column(String)
    timestamp = Column(String)
    uid = Column(String)

ClientData.tags = relationship("Tag",back_populates="client")

class AdminUser(Base):
    __tablename__ = 'adminmanagement'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    profile: Mapped[str] = mapped_column(String(10), nullable=False)
    permission: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[str] = mapped_column(TIMESTAMP, server_default=func.now())
    updated_at: Mapped[str] = mapped_column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
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
                status_code=409,
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
    skip=0
    limit=1000
    try:
       clients = db.query(ClientData).all()
       print(f"Queried {len(clients)} clients")
       if not clients:
           raise HTTPException(
           status_code=200,
           detail='No client is register'
           )
       return clients
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def add_tag_in_database(tagdata):
    print(tagdata)
    db = SessionLocal()
    added_clients = []
    try:
        #client = db.query(Client).filter(Client.user_id == userId).first()
        # Check if the email or phone already exists
        for data in tagdata:
              existing_client = db.query(Tag).filter(
                  (Tag.uid == data.uid) 
                  ).first()

              if existing_client:
                   #raise HTTPException(
                          #status_code=400,
                          #detail="uid already exists."
                   #)
                   print("uid already exist")
                   continue
              db_client = Tag(
                uid=data.uid,
                encryptedfiledata=data.filedata,
                sdmreadcnt=data.readcnt,
                fraud=0,
                blacklistvalue=False,
                counter = data.readcnt,
                proccessedcnt = 0,
                tagactivateddatetime = datetime.now().strftime("%d %B %Y %H:%M:%S"),
                clientid = 12,
                batchno = "MMT-12",
                tagstatus = "Active",
                lastscandatetime = datetime.now().strftime("%d %B %Y %H:%M:%S")

          #password=data.password,
          #accountstatus="Active",
          #registrationdate=datetime.now().strftime("%d-%m-%Y")
              )
              db.add(db_client)
              db.commit()
              db.refresh(db_client)
              added_clients.append(db_client)
        return added_clients
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def get_tags_from_database():
    db = SessionLocal()
    skip=0
    limit=1000
    try:
       tags = db.query(Tag).options(joinedload(Tag.client)).all()
       print(f"Queried {len(tags)} clients")
       #print(tags[0]['username'])
       if not tags:
           raise HTTPException(
           status_code=200,
           detail='No client is register'
           )
       return tags
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
def device_log_in_database(data,uid):
    db = SessionLocal()
    try:
       existing_device_log = db.query(DeviceLog).filter(
               (DeviceLog.systemid == data.systemID)
               ).first()
       if existing_device_log:
           existing_device_log.systemip = data.systemIP
           existing_device_log.systemversion = data.systemVersion
           existing_device_log.timestamp = data.timestamp
           existing_device_log.devicetype = data.deviceType
           existing_device_log.uid = uid
           db.commit()
           db.refresh(existing_device_log)
           print(f"Updated DeviceLog with systemid: {data.systemID}")
           return existing_device_log
       else :
           newDeviceLog = DeviceLog(
                   systemip = data.systemIP,
                   systemid = data.systemID,
                   systemversion = data.systemVersion,
                   timestamp = data.timestamp,
                   devicetype = data.deviceType,
                   uid = uid
                   )
           db.add(newDeviceLog)
           db.commit()
           db.refresh(newDeviceLog)
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
def delete_client_from_database(clientId: int):
    db = SessionLocal()
    print("clientID : ",clientId)
    client = db.query(ClientData).filter(ClientData.id == clientId).first()
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found")
    db.delete(client)
    db.commit()
    return {"message": "Client deleted successfully"}

def update_tag_in_database(id : int, tag):
    db = SessionLocal()
    try:
       existing_tag = db.query(Tag).filter(
            (Tag.id == id)
       ).first()

       if not existing_tag:
           raise HTTPException(
           status_code=200,
           detail='No client is register'
           )
       existing_tag.client.username = tag.client.username
       existing_tag.uid = tag.uid
       existing_tag.batchno = tag.batchno
       existing_tag.tagstatus = tag.tagstatus
       existing_tag.sdmreadcnt = tag.sdmreadcnt
       existing_tag.fraud = tag.fraud
       existing_tag.blacklistvalue = tag.blacklistvalue
       db.commit()
       db.refresh(existing_tag)
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def get_client_api_keys_secrets_from_database():
    db = SessionLocal()
    try:
       client_keys_secret = db.query(ClientData).all()
       if not client_keys_secret:
          raise HTTPException(
          status_code=404,
          detail='No client is register'
          )
       return client_keys_secret  
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def delete_client_api_keys_from_database(clientid: int):
    db = SessionLocal()
    try:
       client_keys_secret = db.query(ClientData).filter(
       (ClientData.id == clientid)
       ).first()
       if not client_keys_secret:
          raise HTTPException(
          status_code=404,
          detail='No client is register'
          )
       client_keys_secret.apikey = ''
       client_keys_secret.secret = ''
       db.commit()
       db.refresh(client_keys_secret)
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def update_client_in_database(clientid :int, data):
    db = SessionLocal()
    print("clientid",clientid)
    try:
       client = db.query(ClientData).filter(
       (ClientData.id == clientid)
       ).first()
       if not client:
          raise HTTPException(
          status_code=404,
          detail='No client is register'
          )
       client.username = data.username
       client.accountstatus = data.accountstatus
       client.email = data.email
       client.industrytype = data.industrytype
       client.companyregtype = data.companyregtype
       db.commit()
       db.refresh(client)
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def add_admin_user_in_database(data):
    db = SessionLocal()
    try:
       user = db.query(AdminUser).filter(
       (AdminUser.email == data.email)
       ).first()
       if not user:
          raise HTTPException(
          status_code=409,
          detail='Already admin user is existed with this email'
          )
       newUser = AdminUser(
          firstname = data.firstname,
          lastname = data.lastname,
          email = data.email,
          password = data.password,
          profile = data.profile,
          permission = data.permission
       )
       db.add(newUser)
       db.commit()
       db.refresh(client)
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def delete_admin_user_from_database(userid: int):
    db = SessionLocal()
    try:
       user = db.query(AdminUser).filter(
       (AdminUser.id == userid)
       ).first()
       if not user:
          raise HTTPException(
          status_code=404,
          detail='No admin user is found'
          )
       db.delete(user)
       db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def update_admin_user_in_database(userid :int, data):
    db = SessionLocal()
    try:
       user = db.query(AdminUser).filter(
       (AdminUser.id == userid)
       ).first()
       if not user:
          raise HTTPException(
          status_code=404,
          detail='No admin user is found'
          )
       user.first_name = data.first_name
       user.last_name = data.last_name
       user.email = data.email
       user.password = data.password
       user.profile = data.profile
       user.permission = data.permission
       db.commit()
       db.refresh(user)
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def get_admin_user_from_database(emailid: str = None):
    db: Session = SessionLocal()
    try:
        if emailid:
            user = db.query(AdminUser).filter(AdminUser.email == emailid).first()
            if not user:
                raise HTTPException(
                    status_code=404,
                    detail='User not found'
                )
            return [user]
        else:
            users = db.query(AdminUser).all()
            if not users:
                raise HTTPException(
                    status_code=200,
                    detail='No users found'
                )
            return users
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
    finally:
        db.close()

def get_device_logs_from_database():
    db = SessionLocal()
    skip=0
    limit=1000
    try:
       device_logs = db.query(DeviceLog).all()
       print(f"Queried {len(device_logs)} device logs")
       #print(tags[0]['username'])
       if not device_logs:
           raise HTTPException(
           status_code=200,
           detail='No device log is found'
           )
       return device_logs
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

