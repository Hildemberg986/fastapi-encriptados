from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import List
import requests
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from dotenv import load_dotenv
from os import getenv

# Carregar variáveis de ambiente do arquivo .env
load_dotenv()

# Obter variáveis de ambiente
usernameEnv = getenv("VAR-USERNAME")
passwordEnv = getenv("VAR-PASSWORD")

# Inicializar o aplicativo FastAPI
app = FastAPI()

# Configuração do CORS (Cross-Origin Resource Sharing)
origins = [
    "https://encriptados.netlify.app",
    "https://encriptados.netlify.app/loja",
]

# Adicionar middleware para configurar o CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configurações de segurança e autenticação JWT
SECRET_KEY = "your-secret-key"  # Chave secreta para assinar o token JWT
ALGORITHM = "HS256"  # Algoritmo de criptografia usado para assinar o token JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Tempo de expiração do token de acesso em minutos

# Configuração do esquema de autenticação OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Função para verificar se o token JWT fornecido é válido
def is_token_valid(authorization: str = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Authorization header is missing")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = parts[1]
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Definição do modelo de item
class Item(BaseModel):
    nome: str
    valor: str
    descricao: str
    imagem: str
    link: str

# Chaves de acesso do RestDB
RESTDB_TOKEN = getenv("TOKENDB")
url = getenv("URLDB")
headers = {
    'content-type': 'application/json',
    'x-apikey': RESTDB_TOKEN
}

# Rota para home (somente para administradores)
@app.get('/')
def home(authorization: str = Header(None)):
    """
    Rota para obter todos os itens da loja.
    Requer um token JWT de autenticação no cabeçalho Authorization.
    """
    try:
        is_token_valid(authorization)
    except HTTPException as e:
        return e

    r = requests.get(url, headers=headers)
    return {"data": r.json()}

# Rota para criar item (somente para administradores)
@app.post("/items/")
async def create_item(item: Item, authorization: str = Header(None)):
    """
    Rota para criar um novo item na loja.
    Requer um token JWT de autenticação no cabeçalho Authorization.
    """
    try:
        is_token_valid(authorization)
    except HTTPException as e:
        return e

    item_dict = item.dict()
    r = requests.post(url, json=item_dict, headers=headers)
    return r.json()

# Rota para deletar item (somente para administradores)
@app.delete("/items/{item_id}")
async def delete_item(item_id: str, authorization: str = Header(None)):
    """
    Rota para deletar um item da loja pelo seu ID.
    Requer um token JWT de autenticação no cabeçalho Authorization.
    """
    try:
        is_token_valid(authorization)
    except HTTPException as e:
        return e

    delete_url = f"{url}/{item_id}"
    r = requests.delete(delete_url, headers=headers)
    return r.json()

# Rota para atualizar item (somente para administradores)
@app.put("/items/{item_id}")
async def update_item(item_id: str, item: Item, authorization: str = Header(None)):
    """
    Rota para atualizar um item da loja pelo seu ID.
    Requer um token JWT de autenticação no cabeçalho Authorization.
    """
    try:
        is_token_valid(authorization)
    except HTTPException as e:
        return e

    update_url = f"{url}/{item_id}"
    item_dict = item.dict()
    r = requests.put(update_url, json=item_dict, headers=headers)
    return r.json()

# Rota para autenticar usuário e gerar token JWT
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Rota para autenticar o usuário e gerar um token JWT.
    """
    user = form_data.username
    password = form_data.password
    if user == usernameEnv and password == passwordEnv:  # Verificação de credenciais (substitua por sua lógica de autenticação)
        token = jwt.encode({"sub": user}, SECRET_KEY, algorithm=ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

# Iniciar o servidor de desenvolvimento usando Uvicorn
if __name__ == "__main__":
    uvicorn.run(app)
