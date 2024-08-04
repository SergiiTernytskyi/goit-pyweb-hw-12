from typing import Optional
from datetime import date, datetime
from pydantic import BaseModel, EmailStr, Field


class UserModel(BaseModel):
    username: str = Field(min_length=5, max_length=16)
    email: str
    password: str = Field(min_length=6, max_length=10)


class UserDbModel(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        orm_mode = True


class UserResponse(BaseModel):
    user: UserDbModel
    detail: str = "User successfully created"


class TokenModel(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
