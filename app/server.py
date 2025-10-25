from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Iterator, Optional
import fastapi
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta
from jose import JWTError, jwt
from fastapi.responses import FileResponse
import os
import httpx
from pydantic import BaseModel

# ЗАЩИТА
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.pydant import User as DbUser, UserCreate, PostResponse, PostCreate, Token, Name_JWT, LocationCreate, LocationResponse
from app.db.models import User, Post, Location
from app.db.database import engine, sesion_local, Base
from app.auth import get_password_hash, verify_password, create_acces_token
from app.config import ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM

app = FastAPI(title="Gachi Muchenicki API", version="1.0.0")

# CORS для фронтенда
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/gachi_muchenicki/login")

# ЗАЩИТА
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

Base.metadata.create_all(bind=engine)

# DataBase
def get_db() -> Iterator[Session]:
    db = sesion_local()
    try:
        yield db
    finally:
        db.close()

# верификация токена
def verify_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        return Name_JWT(email=email)
    except JWTError:
        raise credentials_exception

# ГЛАВНАЯ СТРАНИЦА
@app.get("/gachi_muchenicki/")
@limiter.limit("20/minute")
async def main_page(request: Request):
    return {
        "message": "Добро пожаловать в Gachi Muchenicki API!",
        "endpoints": {
            "register": "POST /gachi_muchenicki/register/",
            "login": "POST /gachi_muchenicki/login/", 
            "profile": "GET /gachi_muchenicki/profile/",
            "map": "GET /gachi_muchenicki/map/"
        },
        "version": "1.0.0"
    }

# РЕГИСТРАЦИЯ
@app.post("/gachi_muchenicki/register/", response_model=DbUser, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def create_user(
    user: UserCreate, 
    db: Session = Depends(get_db), 
    request: Request = None
) -> User:
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user is not None:
        raise HTTPException(status_code=409, detail="Email already registered!")
    
    hash_user_pass = get_password_hash(user.password)

    db_user = User(
        name=user.name, 
        age=user.age, 
        town=user.town, 
        email=user.email, 
        hash_password=hash_user_pass
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user

# ВХОД
@app.post("/gachi_muchenicki/login/", response_model=Token)
@limiter.limit("10/minute")
async def login_users(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    request: Request = None
) -> dict:
    db_user = db.query(User).filter(User.email == form_data.username).first()
    
    if db_user is None:
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    if not verify_password(form_data.password, db_user.hash_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token = create_acces_token(
        data={"sub": db_user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {"access_token": access_token, "token_type": "bearer"}

# ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ
@app.get("/gachi_muchenicki/profile/", response_model=DbUser)
@limiter.limit("20/minute")
async def get_user_profile(
    current_user: Name_JWT = Depends(verify_token),
    db: Session = Depends(get_db),
    request: Request = None
):
    db_user = db.query(User).filter(User.email == current_user.email).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

# ГЕОКОДИРОВАНИЕ - поиск по названию
@app.get("/gachi_muchenicki/geocode/")
@limiter.limit("30/minute")
async def geocode_location(query: str):
    """
    Геокодирование адреса через Nominatim (OpenStreetMap)
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://nominatim.openstreetmap.org/search",
                params={
                    "q": query,
                    "format": "json",
                    "limit": 10,
                    "accept-language": "ru"
                }
            )
            
            if response.status_code == 200:
                results = response.json()
                return [
                    {
                        "name": result.get("display_name", ""),
                        "lat": float(result["lat"]),
                        "lon": float(result["lon"])
                    }
                    for result in results
                ]
            else:
                return []
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Geocoding error: {str(e)}")

# ОБРАТНОЕ ГЕОКОДИРОВАНИЕ - получение адреса по координатам
@app.get("/gachi_muchenicki/reverse-geocode/")
@limiter.limit("30/minute")
async def reverse_geocode(lat: float, lon: float):
    """
    Обратное геокодирование координат в адрес
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://nominatim.openstreetmap.org/reverse",
                params={
                    "lat": lat,
                    "lon": lon,
                    "format": "json",
                    "accept-language": "ru"
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "name": result.get("display_name", ""),
                    "address": result.get("address", {})
                }
            else:
                return {"name": "Неизвестное место", "address": {}}
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reverse geocoding error: {str(e)}")

# СТРАНИЦА КАРТЫ (HTML)
@app.get("/gachi_muchenicki/map/")
@limiter.limit("20/minute")
async def serve_map_page(
    request: Request,
):
    html_file_path = "frontend/index.html"
    
    if not os.path.exists(html_file_path):
        raise HTTPException(status_code=404, detail="Map page not found")
    
    return FileResponse(html_file_path)

# ЛОГИН ДЛЯ ФРОНТЕНДА - ПРОСТОЙ ВАРИАНТ
@app.post("/gachi_muchenicki/simple-login/")
async def simple_login(request: Request, db: Session = Depends(get_db)):
    try:
        form_data = await request.form()
        email = form_data.get("email")
        password = form_data.get("password")
        
        if not email or not password:
            raise HTTPException(status_code=400, detail="Email and password required")
        
        # Ищем пользователя по email
        db_user = db.query(User).filter(User.email == email).first()
        
        if db_user is None:
            raise HTTPException(status_code=401, detail="Incorrect email or password")

        if not verify_password(password, db_user.hash_password):
            raise HTTPException(status_code=401, detail="Incorrect email or password")
        
        # Перенаправляем на карту
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/gachi_muchenicki/map/", status_code=303)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))