from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from db import Base, engine, SessionLocal
from models import Usuario
from schemas import UserCreate, UserLogin
from auth import hash_password, verify_password

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
async def register(user:UserCreate, db: Session = Depends(get_db)):
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
async def login(user:UserLogin, db: Session = Depends(get_db)):
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
# Endpoint: Root, check api status
# ---------------------------
@app.get("/")
def read_root():
    return {"status": "ok"}
