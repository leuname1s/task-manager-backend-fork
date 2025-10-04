from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from db import Base, engine, SessionLocal
from models import Usuario
from auth import hash_password, verify_password

Base.metadata.create_all(bind=engine)

app = FastAPI()

# Dependencia: obtener sesión
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------------
# Endpoint: Registrar usuario
# ---------------------------
@app.post("/register")
def register(correo: str, nombre: str, contrasena: str, db: Session = Depends(get_db)):
    correo = correo.lower()
    # Revisar si el correo ya existe
    if db.query(Usuario).filter_by(correo=correo).first():
        raise HTTPException(status_code=400, detail="Correo ya registrado")
    
    # Crear usuario con contraseña hasheada
    nuevo_usuario = Usuario(
        correo=correo,
        nombre=nombre,
        contrasena=hash_password(contrasena)
    )
    db.add(nuevo_usuario)
    db.commit()
    db.refresh(nuevo_usuario)
    
    return {"mensaje": "Usuario registrado exitosamente", "usuario": nuevo_usuario.nombre}

# ---------------------------
# Endpoint: Iniciar sesión
# ---------------------------
@app.post("/login")
def login(correo: str, contrasena: str, db: Session = Depends(get_db)):
    correo = correo.lower()
    
    usuario = db.query(Usuario).filter_by(correo=correo).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if not verify_password(contrasena, usuario.contrasena):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")
    return {"mensaje": "Inicio de sesión exitoso", "usuario": usuario.nombre}
