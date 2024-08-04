from typing import List
from datetime import date

from fastapi import APIRouter, HTTPException, Depends, Path, Query, status, Security
from fastapi.security import (
    OAuth2PasswordRequestForm,
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.schemas.users import UserModel, UserResponse, TokenModel
from src.repository import users as repository_users
from src.services.auth import auth_service


router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer()


@router.post(
    "/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def signup(body: UserModel, db=Depends(get_db)):
    existing_user = await repository_users.get_user_by_email(body.email, db)

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Account already exists"
        )
    body.password = auth_service.create_hashed_password(body.password)
    new_user = await repository_users.create_user(body, db)
    return {"user": new_user, "detail": "User successfully created"}


@router.post("/signin", response_model=TokenModel)
async def signin(body: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    user = await repository_users.get_user_by_email(body.username, db)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        )

    if not auth_service.verify_password(body.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        )

    access_token = await auth_service.create_access_token(data={"sub": user.email})
    refresh_token = await auth_service.create_refresh_token(data={"sub": user.email})

    await repository_users.update_token(user, refresh_token, db)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.get("/refresh_token", response_model=TokenModel)
async def refresh_token(
    credentials: HTTPAuthorizationCredentials = Security(security), db=Depends(get_db)
):
    token = credentials.credentials
    email = await auth_service.decode_refresh_token(token)
    user = await repository_users.get_user_by_email(email, db)

    if user.refresh_token != token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    access_token = await auth_service.create_access_token(data={"sub": email})
    refresh_token = await auth_service.create_refresh_token(data={"sub": email})

    await repository_users.update_token(user, refresh_token, db)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }
