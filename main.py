from fastapi import FastAPI, Depends, Header, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
import os
import requests
import secrets
from typing import Dict, Annotated, List
from db import Base, engine
from models import *
from schemas import *
from dotenv import load_dotenv
from auth import hash_password, verify_password
from utils import get_db, send_email

load_dotenv()
SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

LOCK_TIME_MINUTES = 5
MAX_ATTEMPTS = 4
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
        
        if usuario.bloqueado:
            if usuario.ultimo_intento_fallido and datetime.now() - usuario.ultimo_intento_fallido < timedelta(minutes=LOCK_TIME_MINUTES):
                return JSONResponse(status_code=403, content={"error":"Cuenta bloqueada temporalmente, intente más tarde"})
            else:
                # Se desbloquea automáticamente pasado el tiempo
                usuario.bloqueado = False
                usuario.intentos_fallidos = 0
            
        contraseñas = db.query(Usuario.contrasena)
        for con in contraseñas:
            if verify_password(user.contraseña, con[0]):
                usuario.bloqueado = False
                usuario.intentos_fallidos = 0
                db.commit()
                return JSONResponse(status_code=200, content={"message": "Inicio de sesión exitoso", "usuario": usuario.nombre, "id": usuario.id,"nombre": usuario.nombre,"correo": usuario.correo})
        
        usuario.intentos_fallidos += 1
        usuario.ultimo_intento_fallido = datetime.now()
        
        if usuario.intentos_fallidos >= MAX_ATTEMPTS:
            usuario.bloqueado = True
            db.commit()
            return JSONResponse(status_code=403, content={"error":"Demasiados intentos fallidos, cuenta bloqueada temporalmente"})

        db.commit()
        return JSONResponse(status_code=401, content={"error": "Contraseña incorrecta"})
    
    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    
    except Exception as e:
        db.rollback()
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
# Endpoint: resetear contraseña
# ---------------------------
@app.post("/reset-password")
def reset_password(credentials:ResetPasswordRequest, db: Session = Depends(get_db)):
    try:
        email = credentials.correo
        new_password = credentials.nueva_contraseña
        
        user = db.query(Usuario).filter(Usuario.correo == email).first()
        if not user:
            return JSONResponse(status_code=404, content={"error":"Usuario no encontrado"})

        # db_token = db.query(RecuperarContrasenaToken).filter_by(usuario_id=user.id, token=token, utilizado=False).first()
        # if not db_token or db_token.expiracion < datetime.now():
        #     return JSONResponse(status_code=400, content={"error":"Código inválido o expirado"})

        # Actualizar contraseña
        user.contrasena = hash_password(new_password)
        # db_token.utilizado = True
        db.commit()

        return {"message": "Contraseña actualizada correctamente"}
    
    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})   
    except Exception as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})

# ---------------------------
# Endpoint: crear proyecto
# ---------------------------
@app.post("/proyectos")
def crear_proyecto(proyecto: ProyectoCreate, x_user_mail: Annotated[str, Header(...)], db: Session = Depends(get_db)):
    try:
        correo = x_user_mail.lower()
        dueño = db.query(Usuario).filter(Usuario.correo == correo).first()
        if not dueño:
            return JSONResponse(status_code=404, content={"error": "Correo de usuario no encontrado"})

        nuevo_proyecto = Proyecto(
            nombre=proyecto.nombre,
            descripcion=proyecto.descripcion,
            id_dueño=dueño.id
        )
        db.add(nuevo_proyecto)
        db.commit()
        
        integrante_dueño = ProyectoIntegrante(
            id_proyecto = nuevo_proyecto.id,
            id_usuario = dueño.id,
            rol = RolProyecto.dueño
        )
        db.add(integrante_dueño)
        db.commit()
        db.refresh(nuevo_proyecto)

        return JSONResponse(status_code=201, content={"message": "proyecto creado exitosamente", "id_proyecto": nuevo_proyecto.id})

    except IntegrityError as e:
        db.rollback()
        return JSONResponse(status_code=400, content={"error": "Error de integridad: " + str(e.orig)})
    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    except Exception as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})

# ---------------------------
# Endpoint: listar proyectos de un usuario por correo
# ---------------------------
@app.get("/proyectos", response_model=List[ProyectoUsuarioInfo])
def listar_proyectos_usuario(x_user_mail: Annotated[str, Header(...)], db: Session = Depends(get_db)):
    try:
        correo = x_user_mail.lower()
        usuario = db.query(Usuario).filter(Usuario.correo == correo).first()
        if not usuario:
            raise JSONResponse(status_code=404, content={"error":"Correo de usuario no encontrado"})

        resultado: List[dict] = []

        # Proyectos donde es integrante (puede solaparse con dueño, se sobreescribe si es dueño)
        for integrante in usuario.proyectos_integrante:
            proj = getattr(integrante, "proyecto", None)
            if proj:
                rol = getattr(integrante, "rol", None)
                rol_str = rol.value if hasattr(rol, "value") else str(rol) if rol else ""
                resultado.append({
                    "id": proj.id,
                    "nombre_proyecto": proj.nombre,
                    "descripcion": proj.descripcion,
                    "fecha_finalizacion": proj.fecha_limite,
                    "rol_usuario": rol_str
                })

        return resultado

    except SQLAlchemyError as e:
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})

# ---------------------------
# Endpoint: eliminar proyecto 
# ---------------------------
@app.delete("/proyectos/{proyecto_id}")
def eliminar_proyecto(proyecto_id: int, x_user_mail: Annotated[str, Header(...)], db: Session = Depends(get_db)):
    try:
        correo = x_user_mail.lower()
        dueño = db.query(Usuario).filter(Usuario.correo == correo).first()
        if not dueño:
            return JSONResponse(status_code=404, content={"error": "Usuario no encontrado"})

        proyecto = db.query(Proyecto).filter(Proyecto.id == proyecto_id).first()
        if not proyecto:
            return JSONResponse(status_code=404, content={"error": "Proyecto no encontrado"})

        if proyecto.id_dueño != dueño.id:
            return JSONResponse(status_code=403, content={"error": "No autorizado: no sos el dueño del proyecto"})

        db.delete(proyecto)
        db.commit()

        return JSONResponse(status_code=200, content={"message": "Proyecto eliminado correctamente", "id_proyecto": proyecto_id})

    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    except Exception as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})

# ---------------------------
# Endpoint: agregar integrantes
# ---------------------------
@app.post("/proyectos/{proyecto_id}/integrantes")
def agregar_integrantes(
    proyecto_id: int,
    x_user_mail: Annotated[str, Header(...)],
    integrantes_req: IntegrantesAddRequest = Body(...),
    db: Session = Depends(get_db)
):
    try:
        correo = x_user_mail.lower()
        dueño = db.query(Usuario).filter(Usuario.correo == correo).first()
        if not dueño:
            return JSONResponse(status_code=404, content={"error": "Usuario no encontrado"})

        proyecto = db.query(Proyecto).filter(Proyecto.id == proyecto_id).first()
        if not proyecto:
            return JSONResponse(status_code=404, content={"error": "Proyecto no encontrado"})

        if proyecto.id_dueño != dueño.id:
            return JSONResponse(status_code=403, content={"error": "No autorizado: no sos el dueño del proyecto"})

        mapping: Dict[str, str] = integrantes_req.root

        # Validar roles y usuarios
        roles_invalid = []
        usuarios_no_existentes = []
        ya_integrantes = []

        for email_raw, rol in mapping.items():
            email = email_raw.lower()
            if rol not in ("editor", "lector"):
                roles_invalid.append({email: rol})
                continue

            usuario = db.query(Usuario).filter(Usuario.correo == email).first()
            if not usuario:
                usuarios_no_existentes.append(email)
                continue

            existe = db.query(ProyectoIntegrante).filter(
                ProyectoIntegrante.id_proyecto == proyecto_id,
                ProyectoIntegrante.id_usuario == usuario.id
            ).first()
            if existe:
                ya_integrantes.append(email)

        if roles_invalid or usuarios_no_existentes or ya_integrantes:
            return JSONResponse(status_code=400, content={
                "error": "Validación fallida",
                "roles_invalidos": roles_invalid,
                "usuarios_no_existentes": usuarios_no_existentes,
                "ya_integrantes": ya_integrantes
            })

        # Agregar integrantes
        creados = []
        for email_raw, rol in mapping.items():
            email = email_raw.lower()
            usuario = db.query(Usuario).filter(Usuario.correo == email).first()
            # usuario y rol ya validados
            role_enum = RolProyecto(rol)  # crear a partir del valor
            nuevo = ProyectoIntegrante(
                id_proyecto=proyecto_id,
                id_usuario=usuario.id,
                rol=role_enum
            )
            db.add(nuevo)
            creados.append({"email": email, "rol": rol})

        db.commit()

        return JSONResponse(status_code=201, content={"message": "Integrantes agregados exitosamente", "integrantes": creados})

    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    except Exception as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})
    
# ---------------------------
# Endpoint: eliminar integrante
# ---------------------------
@app.delete("/proyectos/{proyecto_id}/integrantes")
def eliminar_integrante(
    proyecto_id: int,
    x_user_mail: Annotated[str, Header(...)],
    payload: IntegranteRemoveRequest = Body(...),
    db: Session = Depends(get_db)
):
    try:
        correo_dueño = x_user_mail.lower()
        dueño = db.query(Usuario).filter(Usuario.correo == correo_dueño).first()
        if not dueño:
            return JSONResponse(status_code=404, content={"error": "Usuario no encontrado"})

        proyecto = db.query(Proyecto).filter(Proyecto.id == proyecto_id).first()
        if not proyecto:
            return JSONResponse(status_code=404, content={"error": "Proyecto no encontrado"})

        if proyecto.id_dueño != dueño.id:
            return JSONResponse(status_code=403, content={"error": "No autorizado: no sos el dueño del proyecto"})

        correo_objetivo = payload.correo.lower()
        usuario = db.query(Usuario).filter(Usuario.correo == correo_objetivo).first()
        if not usuario:
            return JSONResponse(status_code=404, content={"error": "Usuario a eliminar no existe"})

        # Evitar eliminar al dueño por este endpoint
        if usuario.id == proyecto.id_dueño:
            return JSONResponse(status_code=400, content={"error": "No se puede eliminar al dueño del proyecto"})

        integrante = db.query(ProyectoIntegrante).filter(
            ProyectoIntegrante.id_proyecto == proyecto_id,
            ProyectoIntegrante.id_usuario == usuario.id
        ).first()
        if not integrante:
            return JSONResponse(status_code=404, content={"error": "El usuario no es integrante del proyecto"})

        db.delete(integrante)
        db.commit()
        return JSONResponse(status_code=200, content={"message": "Integrante eliminado correctamente", "correo": correo_objetivo, "id_proyecto": proyecto_id})

    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    except Exception as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})    

# ---------------------------
# Endpoint: crear tarea en proyecto
# ---------------------------
@app.post("/proyectos/{proyecto_id}/tareas")
def crear_tarea_en_proyecto(
    proyecto_id: int,
    x_user_email: Annotated[str, Header(...)],
    payload: TareaCreate = Body(...),
    db: Session = Depends(get_db)
):
    try:
        correo = x_user_email.lower()
        usuario = db.query(Usuario).filter(Usuario.correo == correo).first()
        if not usuario:
            return JSONResponse(status_code=404, content={"error": "Usuario no encontrado"})

        proyecto = db.query(Proyecto).filter(Proyecto.id == proyecto_id).first()
        if not proyecto:
            return JSONResponse(status_code=404, content={"error": "Proyecto no encontrado"})

        # verificar rol: dueño del proyecto o integrante con rol editor
        autorizado = False
        if proyecto.id_dueño == usuario.id:
            autorizado = True
        else:
            integrante = db.query(ProyectoIntegrante).filter(
                ProyectoIntegrante.id_proyecto == proyecto_id,
                ProyectoIntegrante.id_usuario == usuario.id
            ).first()
            if integrante and integrante.rol in (RolProyecto.editor, RolProyecto.dueño):
                autorizado = True

        if not autorizado:
            return JSONResponse(status_code=403, content={"error": "No autorizado: se requiere rol 'editor' o ser dueño del proyecto"})

        nueva_tarea = Tarea(
            id_proyecto=proyecto_id,
            titulo=payload.titulo,
            descripcion=payload.descripcion,
            fecha_limite=payload.fecha_limite
        )
        db.add(nueva_tarea)
        db.commit()
        db.refresh(nueva_tarea)

        return JSONResponse(status_code=201, content={"message": "tarea creada exitosamente", "id_tarea": nueva_tarea.id})

    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    except Exception as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})

# ---------------------------
# Endpoint: listar tareas en proyecto
# ---------------------------
@app.get("/proyectos/{proyecto_id}/tareas", response_model=List[TareaResponse])
def listar_tareas_proyecto(
    proyecto_id: int,
    x_user_mail: Annotated[str, Header(...)],
    db: Session = Depends(get_db)
):
    try:
        correo = x_user_mail.lower()
        usuario = db.query(Usuario).filter(Usuario.correo == correo).first()
        if not usuario:
            return JSONResponse(status_code=404, content={"error": "Usuario no encontrado"})

        proyecto = db.query(Proyecto).filter(Proyecto.id == proyecto_id).first()
        if not proyecto:
            return JSONResponse(status_code=404, content={"error": "Proyecto no encontrado"})

        # Verificar que el usuario sea dueño o integrante del proyecto
        if proyecto.id_dueño != usuario.id:
            integrante = db.query(ProyectoIntegrante).filter(
                ProyectoIntegrante.id_proyecto == proyecto_id,
                ProyectoIntegrante.id_usuario == usuario.id
            ).first()
            if not integrante:
                return JSONResponse(status_code=403, content={"error": "No autorizado: no sos integrante del proyecto"})

        tareas = db.query(Tarea).filter(Tarea.id_proyecto == proyecto_id).all()
        resultado: List[dict] = []
        for tarea in tareas:
            responsables_list = []
            for tr in getattr(tarea, "responsables", []):
                if getattr(tr, "usuario", None):
                    responsables_list.append({
                        "id": tr.usuario.id,
                        "nombre": tr.usuario.nombre
                    })

            resultado.append({
                "id": tarea.id,
                "id_proyecto": tarea.id_proyecto,
                "titulo": tarea.titulo,
                "descripcion": tarea.descripcion,
                "estado": tarea.estado.value if hasattr(tarea.estado, "value") else str(tarea.estado),
                "fecha_creacion": tarea.fecha_creacion,
                "fecha_limite": tarea.fecha_limite,
                "responsables": responsables_list
            })

        return resultado

    except SQLAlchemyError as e:
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})
    
@app.delete("/proyectos/{proyecto_id}/tareas/{tarea_id}")
def eliminar_tarea(
    proyecto_id: int,
    tarea_id: int,
    x_user_mail: Annotated[str, Header(...)],
    db: Session = Depends(get_db)
):
    try:
        correo = x_user_mail.lower()
        usuario = db.query(Usuario).filter(Usuario.correo == correo).first()
        if not usuario:
            return JSONResponse(status_code=404, content={"error": "Usuario no encontrado"})

        proyecto = db.query(Proyecto).filter(Proyecto.id == proyecto_id).first()
        if not proyecto:
            return JSONResponse(status_code=404, content={"error": "Proyecto no encontrado"})

        # Verificar permiso: dueño o integrante con rol editor
        if proyecto.id_dueño != usuario.id:
            integrante = db.query(ProyectoIntegrante).filter(
                ProyectoIntegrante.id_proyecto == proyecto_id,
                ProyectoIntegrante.id_usuario == usuario.id
            ).first()
            if not integrante or integrante.rol != RolProyecto.editor:
                return JSONResponse(status_code=403, content={"error": "No autorizado: se requiere rol 'editor' o ser dueño del proyecto"})

        tarea = db.query(Tarea).filter(Tarea.id == tarea_id, Tarea.id_proyecto == proyecto_id).first()
        if not tarea:
            return JSONResponse(status_code=404, content={"error": "Tarea no encontrada en el proyecto"})

        db.delete(tarea)
        db.commit()
        return JSONResponse(status_code=200, content={"message": "Tarea eliminada correctamente", "id_tarea": tarea_id})

    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    except Exception as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})

# ---------------------------
# Endpoint: agregar responsables a una tarea
# ---------------------------
@app.post("/proyectos/{proyecto_id}/tareas/{tarea_id}/responsables")
def agregar_responsables_tarea(
    proyecto_id: int,
    tarea_id: int,
    x_user_mail: Annotated[str, Header(...)],
    payload: ResponsablesAddRequest = Body(...),
    db: Session = Depends(get_db)
):
    try:
        correo = x_user_mail.lower()
        usuario = db.query(Usuario).filter(Usuario.correo == correo).first()
        if not usuario:
            return JSONResponse(status_code=404, content={"error": "Usuario (usuario) no encontrado"})

        proyecto = db.query(Proyecto).filter(Proyecto.id == proyecto_id).first()
        if not proyecto:
            return JSONResponse(status_code=404, content={"error": "Proyecto no encontrado"})

        tarea = db.query(Tarea).filter(Tarea.id == tarea_id, Tarea.id_proyecto == proyecto_id).first()
        if not tarea:
            return JSONResponse(status_code=404, content={"error": "Tarea no encontrada en el proyecto"})

        # verificar permiso: dueño o integrante con rol editor
        autorizado = False
        if proyecto.id_dueño == usuario.id:
            autorizado = True
        else:
            integrante = db.query(ProyectoIntegrante).filter(
                ProyectoIntegrante.id_proyecto == proyecto_id,
                ProyectoIntegrante.id_usuario == usuario.id
            ).first()
            if integrante and integrante.rol == RolProyecto.editor:
                autorizado = True

        if not autorizado:
            return JSONResponse(status_code=403, content={"error": "No autorizado: se requiere rol 'editor' o ser dueño del proyecto"})

        correos_raw = list(set(payload.correos))
        no_existentes = []
        no_existentes_en_proyecto = []
        ya_responsables = []
        agregados = []

        for mail in correos_raw:
            m = mail.lower()
            usuario = db.query(Usuario).filter(Usuario.correo == m).first()
            if not usuario:
                no_existentes.append(m)
                continue
            
            existe_en_proyecto = db.query(ProyectoIntegrante).filter(
                ProyectoIntegrante.id_usuario == usuario.id,
                ProyectoIntegrante.id_proyecto == proyecto_id
            ).first()
            if not existe_en_proyecto:
                no_existentes_en_proyecto.append(m)
                continue
            
            existe = db.query(TareaResponsable).filter(
                TareaResponsable.id_tarea == tarea_id,
                TareaResponsable.id_usuario == usuario.id
            ).first()
            if existe:
                ya_responsables.append(m)
                continue

            nuevo = TareaResponsable(
                id_tarea = tarea_id,
                id_usuario = usuario.id
            )
            db.add(nuevo)
            agregados.append({"correo": m, "id_usuario": usuario.id, "nombre": usuario.nombre})

        if no_existentes or ya_responsables or no_existentes_en_proyecto:
            db.rollback()
            return JSONResponse(status_code=400, content={
                "error": "Validación fallida",
                "usuarios_no_existentes": no_existentes,
                "usuarios_no_existentes_en_proyecto": no_existentes_en_proyecto,
                "ya_responsables": ya_responsables,
                "validos": agregados
            })

        db.commit()
        return JSONResponse(status_code=201, content={"message": "Responsables agregados", "agregados": agregados})

    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    except Exception as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})

# ---------------------------
# Endpoint: cambiar estado de una tarea
# ---------------------------
@app.put("/proyectos/{proyecto_id}/tareas/{tarea_id}/estado")
def cambiar_estado_tarea(
    proyecto_id: int,
    tarea_id: int,
    x_user_mail: Annotated[str, Header(...)],
    payload: TareaEstadoUpdate = Body(...),
    db: Session = Depends(get_db)
):
    try:
        correo = x_user_mail.lower()
        actor = db.query(Usuario).filter(Usuario.correo == correo).first()
        if not actor:
            return JSONResponse(status_code=404, content={"error": "Usuario no encontrado"})

        proyecto = db.query(Proyecto).filter(Proyecto.id == proyecto_id).first()
        if not proyecto:
            return JSONResponse(status_code=404, content={"error": "Proyecto no encontrado"})

        # verificar permiso: dueño o integrante con rol editor
        autorizado = False
        if proyecto.id_dueño == actor.id:
            autorizado = True
        else:
            integrante = db.query(ProyectoIntegrante).filter(
                ProyectoIntegrante.id_proyecto == proyecto_id,
                ProyectoIntegrante.id_usuario == actor.id
            ).first()
            if integrante and integrante.rol == RolProyecto.editor:
                autorizado = True

        if not autorizado:
            return JSONResponse(status_code=403, content={"error": "No autorizado: se requiere rol 'editor' o ser dueño del proyecto"})

        tarea = db.query(Tarea).filter(Tarea.id == tarea_id, Tarea.id_proyecto == proyecto_id).first()
        if not tarea:
            return JSONResponse(status_code=404, content={"error": "Tarea no encontrada en el proyecto"})

        nuevo_estado = payload.estado


        try:
            # intentar por nombre de miembro
            tarea.estado = EstadoTarea[nuevo_estado]
        except Exception:
            # intentar por valor
            tarea.estado = EstadoTarea(nuevo_estado)


        db.commit()
        db.refresh(tarea)

        return JSONResponse(status_code=200, content={
            "message": "Estado de la tarea actualizado",
            "id_tarea": tarea.id,
            "estado": tarea.estado.value if hasattr(tarea.estado, "value") else str(tarea.estado)
        })

    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error de base de datos: " + str(e)})
    except Exception as e:
        db.rollback()
        return JSONResponse(status_code=500, content={"error": "Error inesperado: " + str(e)})
    
# ---------------------------
# Endpoint: Root, check api status
# ---------------------------
@app.get("/")
def read_root():
    return {"status": "ok"}
