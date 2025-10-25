from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Iterator, Optional
import fastapi
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta
from jose import JWTError, jwt
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
import os
import httpx
from pydantic import BaseModel

from app.pydant import User as DbUser, UserCreate, PostResponse, PostCreate, Token, Name_JWT, LocationCreate, LocationResponse
from app.db.models import User, Post
from app.db.database import engine, sesion_local, Base
from app.auth import get_password_hash, verify_password, create_acces_token
from app.config import ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM
from app.json_storage import location_storage

app = FastAPI(title="Gachi Muchenicki API", version="1.0.0")

# CORS \u0434\u043b\u044f \u0444\u0440\u043e\u043d\u0442\u0435\u043d\u0434\u0430
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/gachi_muchenicki/login")

Base.metadata.create_all(bind=engine)

# DataBase
def get_db() -> Iterator[Session]:
    db = sesion_local()
    try:
        yield db
    finally:
        db.close()

# \u0432\u0435\u0440\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f \u0442\u043e\u043a\u0435\u043d\u0430
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

# \u0413\u041b\u0410\u0412\u041d\u0410\u042f \u0421\u0422\u0420\u0410\u041d\u0418\u0426\u0410 \u0424\u0420\u041e\u041d\u0422\u0415\u041d\u0414\u0410
@app.get("/gachi_muchenicki/", response_class=HTMLResponse)
async def main_page(request: Request):
    try:
        with open("frontend/main.html", "r", encoding="utf-8") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        return {
            "message": "\u0414\u043e\u0431\u0440\u043e \u043f\u043e\u0436\u0430\u043b\u043e\u0432\u0430\u0442\u044c \u0432 Gachi Muchenicki API!",
            "endpoints": {
                "register": "POST /gachi_muchenicki/register/",
                "login": "POST /gachi_muchenicki/login/", 
                "profile": "GET /gachi_muchenicki/profile/",
                "map": "GET /gachi_muchenicki/map/"
            },
            "version": "1.0.0"
        }

# \u0421\u0422\u0420\u0410\u041d\u0418\u0426\u0410 \u0420\u0415\u0413\u0418\u0421\u0422\u0420\u0410\u0426\u0418\u0418 (GET - \u0434\u043b\u044f \u043e\u0442\u0434\u0430\u0447\u0438 HTML)
@app.get("/gachi_muchenicki/register/", response_class=HTMLResponse)
async def serve_register_page(request: Request):
    try:
        with open("frontend/register.html", "r", encoding="utf-8") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Registration page not found")

# \u0421\u0422\u0420\u0410\u041d\u0418\u0426\u0410 \u041b\u041e\u0413\u0418\u041d\u0410
@app.get("/gachi_muchenicki/login/", response_class=HTMLResponse)
async def serve_login_page(request: Request):
    try:
        with open("frontend/login.html", "r", encoding="utf-8") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Login page not found")

# ПРОСТОЙ ЛОГИН ДЛЯ ФРОНТЕНДА - ВОЗВРАЩАЕМ ТОКЕН СРАЗУ
@app.post("/gachi_muchenicki/simple-login/")
async def simple_login(request: Request, db: Session = Depends(get_db)):
    try:
        form_data = await request.form()
        username = form_data.get("username")
        password = form_data.get("password")
        
        print(f"DEBUG: Login attempt - Username: {username}")
        
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")
        
        # Ищем пользователя по имени
        db_user = db.query(User).filter(User.name == username).first()
        
        if db_user is None:
            print(f"DEBUG: User not found with username: {username}")
            raise HTTPException(status_code=401, detail="Incorrect username or password")

        # Проверяем пароль
        if not verify_password(password, db_user.hash_password):
            print(f"DEBUG: Password verification failed for user: {username}")
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        
        print(f"DEBUG: Login successful for user: {username}")
        
        # Создаем токен
        access_token = create_acces_token(
            data={"sub": db_user.email},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        return {
            "access_token": access_token, 
            "token_type": "bearer",
            "message": "Login successful"
        }
        
    except Exception as e:
        print(f"DEBUG: Login error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# API \u0420\u0415\u0413\u0418\u0421\u0422\u0420\u0410\u0426\u0418\u042f (POST - \u0434\u043b\u044f \u043f\u0440\u0438\u0435\u043c\u0430 \u0434\u0430\u043d\u043d\u044b\u0445)
@app.post("/gachi_muchenicki/register/", response_model=DbUser, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    user: UserCreate, 
    db: Session = Depends(get_db)
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

# \u0412\u0425\u041e\u0414 (\u0441\u0442\u0430\u043d\u0434\u0430\u0440\u0442\u043d\u044b\u0439 OAuth2 \u0434\u043b\u044f API)
@app.post("/gachi_muchenicki/login/", response_model=Token)
async def login_users(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
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

# \u041f\u0420\u041e\u0424\u0418\u041b\u042c \u041f\u041e\u041b\u042c\u0417\u041e\u0412\u0410\u0422\u0415\u041b\u042f
@app.get("/gachi_muchenicki/profile/", response_model=DbUser)
async def get_user_profile(
    request: Request,
    current_user: Name_JWT = Depends(verify_token),
    db: Session = Depends(get_db)
):
    db_user = db.query(User).filter(User.email == current_user.email).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

# \u0413\u0415\u041e\u041a\u041e\u0414\u0418\u0420\u041e\u0412\u0410\u041d\u0418\u0415 - \u043f\u043e\u0438\u0441\u043a \u043f\u043e \u043d\u0430\u0437\u0432\u0430\u043d\u0438\u044e
@app.get("/gachi_muchenicki/geocode/")
async def geocode_location(request: Request, query: str):
    """
    \u0413\u0435\u043e\u043a\u043e\u0434\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435 \u0430\u0434\u0440\u0435\u0441\u0430 \u0447\u0435\u0440\u0435\u0437 Nominatim (OpenStreetMap)
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

# \u041e\u0411\u0420\u0410\u0422\u041d\u041e\u0415 \u0413\u0415\u041e\u041a\u041e\u0414\u0418\u0420\u041e\u0412\u0410\u041d\u0418\u0415 - \u043f\u043e\u043b\u0443\u0447\u0435\u043d\u0438\u0435 \u0430\u0434\u0440\u0435\u0441\u0430 \u043f\u043e \u043a\u043e\u043e\u0440\u0434\u0438\u043d\u0430\u0442\u0430\u043c
@app.get("/gachi_muchenicki/reverse-geocode/")
async def reverse_geocode(request: Request, lat: float, lon: float):
    """
    \u041e\u0431\u0440\u0430\u0442\u043d\u043e\u0435 \u0433\u0435\u043e\u043a\u043e\u0434\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435 \u043a\u043e\u043e\u0440\u0434\u0438\u043d\u0430\u0442 \u0432 \u0430\u0434\u0440\u0435\u0441
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
                return {"name": "\u041d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u043e\u0435 \u043c\u0435\u0441\u0442\u043e", "address": {}}
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reverse geocoding error: {str(e)}")

# \u0421\u0422\u0420\u0410\u041d\u0418\u0426\u0410 \u041a\u0410\u0420\u0422\u042b (HTML)
@app.get("/gachi_muchenicki/map/")
async def serve_map_page(request: Request):
    html_file_path = "frontend/index.html"
    
    if not os.path.exists(html_file_path):
        raise HTTPException(status_code=404, detail="Map page not found")
    
    return FileResponse(html_file_path)

# ЭНДПОИНТЫ ДЛЯ РАБОТЫ С ЛОКАЦИЯМИ (JSON)
@app.post("/gachi_muchenicki/locations/", response_model=LocationResponse)
async def create_location(
    location: LocationCreate,
    db: Session = Depends(get_db)
):
    # Берем первого пользователя из БД (или создаем временного)
    db_user = db.query(User).first()
    if not db_user:
        # Если нет пользователей, создаем временного
        db_user = User(
            name="temp_user",
            email="temp@example.com", 
            age=25,
            town="Moscow",
            hash_password="temp"
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    
    location_data = {
        "name": location.name,
        "address": location.address,
        "latitude": location.latitude,
        "longitude": location.longitude,
        "start_time": location.start_time,
        "end_time": location.end_time,
        "break_start": location.break_start,
        "break_end": location.break_end,
        "travel_time": location.travel_time,
        "user_id": db_user.id
    }
    
    created_location = location_storage.create_location(location_data)
    return created_location

@app.get("/gachi_muchenicki/locations/", response_model=List[LocationResponse])
async def get_user_locations(db: Session = Depends(get_db)):
    # Возвращаем все локации (или можно фильтровать по user_id если нужно)
    locations = location_storage._read_locations()
    return locations

@app.patch("/gachi_muchenicki/locations/{location_id}")
async def update_location_travel_time(
    location_id: int,
    travel_time: str,
    db: Session = Depends(get_db)
):
    # Находим локацию по ID и обновляем время
    locations = location_storage._read_locations()
    
    for location in locations:
        if location['id'] == location_id:
            location['travel_time'] = travel_time
            location_storage._write_locations(locations)
            return {"message": "Travel time updated successfully", "location": location}
    
    raise HTTPException(status_code=404, detail="Location not found")

@app.delete("/gachi_muchenicki/locations/{location_id}")
async def delete_location(location_id: int, db: Session = Depends(get_db)):
    # Удаляем локацию по ID
    locations = location_storage._read_locations()
    
    for i, location in enumerate(locations):
        if location['id'] == location_id:
            locations.pop(i)
            location_storage._write_locations(locations)
            return {"message": "Location deleted successfully"}
    
    raise HTTPException(status_code=404, detail="Location not found")
