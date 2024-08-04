from typing import List
from datetime import date

from fastapi import APIRouter, HTTPException, Depends, Path, Query, status
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.schemas.contacts import ContactSchema, ContactResponse, ContactUpdateSchema
from src.repository import contacts as repository_contacts
from src.services.auth import auth_service
from src.database.models import User


router = APIRouter(prefix="/contacts", tags=["contacts"])


@router.get("/", response_model=List[ContactResponse])
async def get_contacts(
    skip: int = 0,
    limit: int = 100,
    first_name: str = None,
    last_name: str = None,
    email: str = None,
    upcomming_birthday: bool = None,
    db: Session = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    contacts = await repository_contacts.get_contacts(
        skip, limit, first_name, last_name, email, upcomming_birthday, db, user
    )
    return contacts


@router.get("/{contact_id}", response_model=ContactResponse)
async def get_contact_by_id(
    contact_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    contact = await repository_contacts.get_contact_by_id(contact_id, db, user)
    return contact


@router.post("/", response_model=ContactResponse, status_code=status.HTTP_201_CREATED)
async def add_contact(
    body: ContactSchema,
    db: Session = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    return await repository_contacts.create_contact(body, db, user)


@router.patch("/{contact_id}", response_model=ContactResponse)
async def update_contact(
    contact_id: int,
    body: ContactUpdateSchema,
    db: Session = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    contact = await repository_contacts.update_contact(contact_id, body, db, user)
    if contact is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found"
        )
    return contact


@router.delete("/{contact_id}", response_model=ContactResponse)
async def delete_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(auth_service.get_current_user),
):
    contact = await repository_contacts.delete_contact(contact_id, db, user)
    if contact is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found"
        )
    return contact
