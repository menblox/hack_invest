from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Iterator
import fastapi
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta
from jose import JWTError, jwt
from fastapi.responses import FileResponse
import os

# ЗАЩИТА
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.pydant import User as DbUser, UserCreate, PostResponse, PostCreate, Token, Name_JWT
from app.db.models import User, Post
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

# ДАННЫЕ ДЛЯ КАРТЫ (JSON)
@app.get("/gachi_muchenicki/map-data/", response_model=List[PostResponse])
@limiter.limit("20/minute")
async def get_map_data(
    #current_user: Name_JWT = Depends(verify_token),
    db: Session = Depends(get_db),
    request: Request = None
) -> List[Post]:
    return db.query(Post).all()

# СТРАНИЦА КАРТЫ (HTML)
@app.get("/gachi_muchenicki/map/")
@limiter.limit("20/minute")
async def serve_map_page(
    request: Request,
    #current_user: Name_JWT = Depends(verify_token),
    db: Session = Depends(get_db)
):
    # Путь к вашему HTML файлу
    html_file_path = "frontend/index.html"
    
    # Проверяем что файл существует
    if not os.path.exists(html_file_path):
        raise HTTPException(status_code=404, detail="Map page not found")
    
    # Отдаем HTML файл
    return FileResponse(html_file_path)