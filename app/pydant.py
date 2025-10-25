from pydantic import BaseModel, EmailStr
from typing import Optional


class UserBase(BaseModel):
    name: str
    age: int
    town: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int

    class Config:
        from_attributes = True

class UserForPost(BaseModel):
    id: int
    name: str
    
    class Config:
        from_attributes = True

class PostBase(BaseModel):
    title: str
    body: str

class PostCreate(PostBase):
    pass

class PostResponse(PostBase):
    id: int
    author: UserForPost

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class Name_JWT(BaseModel):
    email: EmailStr

    class Config:
        from_attributes = True

# СХЕМЫ ДЛЯ ЛОКАЦИЙ (JSON)
class LocationBase(BaseModel):
    name: str
    address: str
    latitude: float
    longitude: float
    start_time: str
    end_time: str
    break_start: str
    break_end: str
    travel_time: Optional[str] = None

class LocationCreate(LocationBase):
    pass

class LocationResponse(LocationBase):
    id: int
    user_id: int

    class Config:
        from_attributes = True