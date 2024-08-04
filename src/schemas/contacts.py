from typing import Optional
from datetime import date, datetime
from pydantic import BaseModel, EmailStr, Field


class ContactSchema(BaseModel):
    first_name: str = Field(min_length=3, max_length=50)
    last_name: str = Field(min_length=3, max_length=50)
    email: EmailStr = Field(min_length=3, max_length=50)
    phone_number: str = Field(min_length=13, max_length=13)
    birth_date: date
    additional_info: Optional[str] = Field(min_length=3, max_length=13)


class ContactUpdateSchema(ContactSchema):
    first_name: Optional[str] = Field(None, min_length=3, max_length=50)
    last_name: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = Field(None, min_length=3, max_length=50)
    phone_number: Optional[str] = Field(None, min_length=13, max_length=13)
    birth_date: Optional[date] = None
    additional_info: Optional[str] = Field(None, min_length=3, max_length=13)


class ContactResponse(ContactSchema):
    id: int = 1
    created_at: datetime

    class Config:
        from_attributes = True
