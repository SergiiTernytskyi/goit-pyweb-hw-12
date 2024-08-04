from sqlalchemy import Column, Integer, String, func, Date
from sqlalchemy.sql.schema import ForeignKey
from sqlalchemy.sql.sqltypes import DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import validates, relationship

Base = declarative_base()


class Contact(Base):
    __tablename__ = "contacts"
    id = Column(Integer, primary_key=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    email = Column(String(50), nullable=False)
    phone_number = Column(String(13), nullable=False)
    birth_date = Column(Date, nullable=False)
    additional_info = Column(String(250), nullable=True)
    created_at = Column("created_at", DateTime, default=func.now())
    user_id = Column(
        "user_id", ForeignKey("users.id", ondelete="CASCADE"), default=None
    )
    user = relationship("User", backref="contacts")

    @validates("phone_number")
    def validate_phone_number(self, key, phone_number):
        if len(phone_number) != 13:
            raise ValueError("Phone number must be 13 characters long")
        return phone_number


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50))
    email = Column(String(250), nullable=False, unique=True)
    password = Column(String(255), nullable=False)
    created_at = Column("crated_at", DateTime, default=func.now())
    refresh_token = Column(String(255), nullable=True)
