from sqlalchemy import Column, Integer, String, ForeignKey, Float
from sqlalchemy.orm import relationship, Mapped
from app.db.database import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    name: Mapped[str] = Column(String, index=True)      # Имя пользователя
    email: Mapped[str] = Column(String, unique=True, index=True)  # Email (уникальный)
    age: Mapped[int] = Column(Integer)                  # Возраст
    town: Mapped[str] = Column(String, index=True)      # Город
    hash_password: Mapped[str] = Column(String)         # Хэшированный пароль

class Post(Base):
    __tablename__ = "posts"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    title: Mapped[str] = Column(String, index=True)
    body: Mapped[str] = Column(String)
    author_id: Mapped[int] = Column(Integer, ForeignKey("users.id"))

    author: Mapped["User"] = relationship("User")

# НОВАЯ МОДЕЛЬ ДЛЯ МЕСТ
class Location(Base):
    __tablename__ = "locations"

    id: Mapped[int] = Column(Integer, primary_key=True, index=True)
    name: Mapped[str] = Column(String, index=True)
    description: Mapped[str] = Column(String)
    latitude: Mapped[float] = Column(Float)
    longitude: Mapped[float] = Column(Float)