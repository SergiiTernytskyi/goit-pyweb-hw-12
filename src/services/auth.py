from typing import Optional

from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.repository import users as repository_users


class Auth:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    SECRET_KEY = "secret_key"
    ALGORITHM = "HS256"
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/signin")

    def verify_password(self, password, hashed_password):
        return self.pwd_context.verify(password, hashed_password)

    def create_hashed_password(self, password):
        return self.pwd_context.hash(password)

    async def create_access_token(self, data, expires_delta=None):
        encoding_data = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + timedelta(seconds=expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(minutes=30)

        encoding_data.update(
            {"iat": datetime.utcnow(), "exp": expire, "scope": "access_token"}
        )

        encoded_access_token = jwt.encode(
            encoding_data, self.SECRET_KEY, algorithm=self.ALGORITHM
        )
        return encoded_access_token

    async def create_refresh_token(self, data, expires_delta=None):
        encoding_data = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + timedelta(seconds=expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(minutes=30)

        encoding_data.update(
            {"iat": datetime.utcnow(), "exp": expire, "scope": "refresh_token"}
        )

        encoded_refresh_token = jwt.encode(
            encoding_data, self.SECRET_KEY, algorithm=self.ALGORITHM
        )
        return encoded_refresh_token

    async def decode_refresh_token(self, refresh_token):
        try:
            payload = jwt.decode(
                refresh_token, self.SECRET_KEY, algorithms=[self.ALGORITHM]
            )
            if payload["scope"] == "refresh_token":
                email = payload["sub"]
                return email

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid scope or token",
            )
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )

    async def get_current_user(self, token=Depends(oauth2_scheme), db=Depends(get_db)):
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload["scope"] == "access_token":
                email = payload["sub"]
                if email is None:
                    raise credentials_exception
        except JWTError as e:
            raise credentials_exception

        user = await repository_users.get_user_by_email(email, db)

        if user is None:
            raise credentials_exception
        return user


auth_service = Auth()
