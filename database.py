from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql://postgres:postgres*123@localhost:5432/postgres"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class TagData(Base):
    __tablename__ = "tag_data"
    id = Column(Integer, primary_key=True, index=True)
    picc_data_tag = Column(String, index=True)
    uid = Column(String, index=True)
    read_ctr = Column(Integer, index=True)
    file_data = Column(String, nullable=True)
    encryption_mode = Column(String, index=True)
    cmac_status = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def store_data_to_database(db, data):
    tag_data = TagData(**data)
    db.add(tag_data)
    db.commit()
    db.refresh(tag_data)
    return tag_data

def verify_uid_in_database(db, iUid):
    return db.query(TagData).filter_by(
        uid=iUid
    ).first() is not None

def verify_read_count_in_database(db, iReadCount):
    return db.query(TagData).filter_by(
        read_ctr=iReadCount
    ).first() is not None
