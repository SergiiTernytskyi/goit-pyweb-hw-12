from datetime import date, datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session

from src.database.models import Contact, User
from src.schemas.contacts import ContactSchema, ContactUpdateSchema


async def get_contacts(
    skip: int,
    limit: int,
    first_name: Optional[str],
    last_name: Optional[str],
    email: Optional[str],
    upcomming_birthday: Optional[bool],
    db: Session,
    user: User,
) -> List[Contact]:

    print(user)

    query = db.query(Contact).filter(Contact.user_id == user.id)

    today_date = datetime.today()
    upcoming_week = today_date + timedelta(days=7)

    if first_name:
        query = query.filter(Contact.first_name == first_name)
    if last_name:
        query = query.filter(Contact.last_name == last_name)
    if email:
        query = query.filter(Contact.email == email)
    if upcomming_birthday:
        query = query.filter(Contact.birth_date.between(today_date, upcoming_week))

    return query.offset(skip).limit(limit).all()


async def get_contact_by_id(
    contact_id: int,
    db: Session,
    user: User,
) -> Contact:
    return (
        db.query(Contact)
        .filter(and_(Contact.id == contact_id, Contact.user_id == user.id))
        .first()
    )


async def create_contact(
    body: ContactSchema,
    db: Session,
    user: User,
) -> Contact:
    contact = Contact(**body.model_dump(exclude_unset=True), user_id=user.id)
    db.add(contact)
    db.commit()
    db.refresh(contact)
    return contact


async def update_contact(
    contact_id: int,
    body: ContactUpdateSchema,
    db: Session,
    user: User,
):
    contact = (
        db.query(Contact)
        .filter(and_(Contact.id == contact_id, Contact.user_id == user.id))
        .first()
    )
    if contact:
        update_data = body.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(contact, key, value)
        db.commit()
        db.refresh(contact)
    return contact


async def delete_contact(
    contact_id: int,
    db: Session,
    user: User,
):
    contact = (
        db.query(Contact)
        .filter(and_(Contact.id == contact_id, Contact.user_id == user.id))
        .first()
    )
    if contact:
        db.delete(contact)
        db.commit()
    return contact
