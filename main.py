from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from db import Base, engine
from models import *
from schemas import *
from auth import hash_password, verify_password
from utils import get_db, send_email
import os
import requests
import secrets
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

Base.metadata.create_all(bind=engine)

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,          # Dominios que pueden acceder
    allow_credentials=True,
    allow_methods=["*"],            # Métodos permitidos (GET, POST, etc.)
    allow_headers=["*"],            # Headers permitidos
)

# Dependencia: obtener sesión



# ---------------------------
# Endpoint: Registrar usuario
# ---------------------------
@app.post("/register")
def register(user:UserCreate, db: Session = Depends(get_db)):
    try:
        correo = user.correo.lower()
        # Revisar si el correo ya existe
        if db.query(Usuario).filter_by(correo=correo).first():
            return JSONResponse(status_code=400, content={"error": "Correo ya registrado"})
        # Crear usuario con contraseña hasheada
        nuevo_usuario = Usuario(
            correo=correo,
            nombre=user.nombre,
            contrasena=hash_password(user.contraseña)
        )
        db.add(nuevo_usuario)
        db.commit()
        db.refresh(nuevo_usuario)
        
        
        return JSONResponse(status_code=201, content={"message": "Usuario registrado exitosamente", "usuario": nuevo_usuario.nombre})
    except IntegrityError as e:
        db.rollback()  # revertir cambios en caso de error
        return JSONResponse(status_code=400, content={"error": "Error de integridad: " + str(e.orig)})
    
    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})

# ---------------------------
# Endpoint: Iniciar sesión
# ---------------------------
@app.post("/login")
def login(user:UserLogin, db: Session = Depends(get_db)):
    try:
        correo = user.correo.lower()
        
        usuario = db.query(Usuario).filter_by(correo=correo).first()
        if not usuario:
            return JSONResponse(status_code=404, content={"error": "Usuario no encontrado"})
        contraseñas = db.query(Usuario.contrasena)
        for con in contraseñas:
            if verify_password(user.contraseña, con[0]):
                return JSONResponse(status_code=200, content={"message": "Inicio de sesión exitoso", "usuario": usuario.nombre})
        return JSONResponse(status_code=401, content={"error": "Contraseña incorrecta"})
    except SQLAlchemyError as e:
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})
    
# ---------------------------
# Endpoint: verificar Captcha
# ---------------------------    
@app.post("/api/verify-captcha")
def verify_captcha(req: CaptchaRequest):
    try:
        url = "https://www.google.com/recaptcha/api/siteverify"
        data = {"secret": SECRET_KEY, "response": req.token}
        r = requests.post(url, data=data)
        result = r.json()
        # print("----")
        # print(result)
        if not result.get("success"):
            return JSONResponse(status_code=400, content={"error": "Captcha inválido"})
        return {"success": True}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})
    
# ---------------------------
# Endpoint: olvide mi contraseña
# ---------------------------
@app.post("/forgot-password")
def forgot_password(email: str, db: Session = Depends(get_db)):
    user = db.query(Usuario).filter(Usuario.correo == email).first()
    if not user:
        return JSONResponse(status_code=404, content={"error":"Usuario no encontrado"})

    token = secrets.token_hex(3)  # código corto, por ejemplo 'a3f9c1'
    expires = datetime.now() + timedelta(minutes=10)

    db_token = RecuperarContrasenaToken(usuario_id=user.id, token=token, expiracion=expires)
    db.add(db_token)
    db.commit()

    send_email(to=email, subject="Recuperación de contraseña", 
               body=f"Tu código de recuperación es: {token}")

    return {"message": "Se envió un código de recuperación a tu correo"}
    
# ---------------------------
# Endpoint: resetear contraseña
# ---------------------------
@app.post("/reset-password")
def reset_password(email: str, token: str, new_password: str, db: Session = Depends(get_db)):
    user = db.query(Usuario).filter(Usuario.correo == email).first()
    if not user:
        return JSONResponse(status_code=404, content={"error":"Usuario no encontrado"})

    db_token = db.query(RecuperarContrasenaToken).filter_by(usuario_id=user.id, token=token, utilizado=False).first()
    if not db_token or db_token.expiracion < datetime.now():
        return JSONResponse(status_code=400, content={"error":"Código inválido o expirado"})

    # Actualizar contraseña
    user.contrasena = hash_password(new_password)
    db_token.utilizado = True
    db.commit()

    return {"message": "Contraseña actualizada correctamente"}

# ---------------------------
# Endpoint: Root, check api status
# ---------------------------
@app.get("/")
def read_root():
    return {"status": "ok"}
