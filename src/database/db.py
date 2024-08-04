from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.config.config import config

engine = create_engine(config.DB_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
