from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import jwt
import requests
from dotenv import load_dotenv
from os import getenv

# Carrega .env
load_dotenv()

# Configs
SECRET_KEY = "sua_chave_secreta"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

usernameEnv = getenv("VAR-USERNAME")
passwordEnv = getenv("VAR-PASSWORD")
RESTDB_TOKEN = getenv("TOKENDB")
URLDB = getenv("URLDB")

# FastAPI app
app = FastAPI(
    title="API Encriptados - Loja",
    description="Use 'Authorize' com seu access_token para acessar rotas protegidas.",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Ajuste se quiser restringir
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Segurança (Bearer Token)
bearer_scheme = HTTPBearer()

# Headers RestDB
headers = {
    "content-type": "application/json",
    "x-apikey": RESTDB_TOKEN
}

# MODELS
class Item(BaseModel):
    nome: str
    valor: str
    descricao: str
    imagem: str
    link: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class AccessTokenOnly(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginInput(BaseModel):
    username: str
    password: str

# UTILS
def create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

# ROTAS

@app.get("/", tags=["Público"])
def public_home():
    """Rota pública que retorna os itens da loja"""
    r = requests.get(URLDB, headers=headers)
    return {"data": r.json()}

@app.post("/auth/login", response_model=TokenResponse, tags=["Autenticação"])
def login(data: LoginInput):
    """
    Autentica e retorna access + refresh tokens.
    """
    if data.username != usernameEnv or data.password != passwordEnv:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    access_token = create_token(
        {"sub": data.username},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_token(
        {"sub": data.username, "type": "refresh"},
        timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/auth/refresh", response_model=AccessTokenOnly, tags=["Autenticação"])
def refresh_token(authorization: Optional[str] = Header(None)):
    """
    Gera novo access_token a partir de refresh_token.
    """
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Cabeçalho Authorization ausente ou inválido")

    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Não é um refresh token")
        new_access = create_token(
            {"sub": payload["sub"]},
            timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": new_access, "token_type": "bearer"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Refresh token inválido")

@app.post("/items", tags=["Itens"], dependencies=[Depends(get_current_user)])
def create_item(item: Item):
    """Cria um novo item (requer token Bearer)"""
    r = requests.post(URLDB, json=item.dict(), headers=headers)
    return r.json()

@app.put("/items/{item_id}", tags=["Itens"], dependencies=[Depends(get_current_user)])
def update_item(item_id: str, item: Item):
    """Atualiza um item (requer token Bearer)"""
    update_url = f"{URLDB}/{item_id}"
    r = requests.put(update_url, json=item.dict(), headers=headers)
    return r.json()

@app.delete("/items/{item_id}", tags=["Itens"], dependencies=[Depends(get_current_user)])
def delete_item(item_id: str):
    """Remove um item da loja (requer token Bearer)"""
    delete_url = f"{URLDB}/{item_id}"
    r = requests.delete(delete_url, headers=headers)
    return r.json()
@app.get("/teste/me")
async def me():
    return {
        "allianceId": 35027,
        "allianceRole": "member",
        "charges": {
            "cooldownMs": 1000,  # aqui você controla o cooldown
            "count": 39.64,
            "max": 79
        },
        "country": "BR",
        "discord": "",
        "droplets": 475,
        "email": "hildembergeling@gmail.com",
        "equippedFlag": 0,
        "extraColorsBitmap": 0,
        "favoriteLocations": [],
        "flagsBitmap": "AA==",
        "id": 815823,
        "isCustomer": False,
        "level": 7.021,
        "maxFavoriteLocations": 15,
        "name": "SharpPlate",
        "needsPhoneVerification": False,
        "picture": "",
        "pixelsPainted": 475,
        "showLastPixel": True
    }
