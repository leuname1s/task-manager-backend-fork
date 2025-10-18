from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, Enum
from sqlalchemy.orm import relationship
from db import Base
import enum

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, autoincrement=True)
    correo = Column(String(120), unique=True, nullable=False, index=True)
    nombre = Column(String(100), nullable=False)
    contrasena = Column(String(200), nullable=False)
    intentos_fallidos = Column(Integer, default=0)
    bloqueado = Column(Boolean, default=False)
    ultimo_intento_fallido = Column(DateTime, default=None)
    
    proyectos_propios = relationship("Proyecto", back_populates="dueño")
    proyectos_integrante = relationship("ProyectoIntegrante", back_populates="usuario")
    tareas_asignadas = relationship("TareaResponsable", back_populates="usuario")
    
    def __repr__(self):
        return f"<Usuario(id={self.id}, correo='{self.correo}', nombre='{self.nombre}')>"
    
class RecuperarContrasenaToken(Base):
    __tablename__ = "recuperarcontrasenatokens"
    id = Column(Integer, primary_key=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))
    token = Column(String, index=True) 
    expiracion = Column(DateTime)
    utilizado = Column(Boolean, default=False)
    usuario = relationship("Usuario")

# ------

class Proyecto(Base):
    __tablename__ = "proyectos"
    id = Column(Integer, primary_key=True)
    nombre = Column(String(100), nullable=False)
    descripcion = Column(Text)
    fecha_creacion = Column(DateTime, default=datetime.now)
    fecha_limite = Column(DateTime)
    
    id_dueño = Column(Integer, ForeignKey("usuarios.id"))
    dueño = relationship("Usuario", back_populates="proyectos_propios")
    
    integrantes = relationship("ProyectoIntegrante", back_populates="proyecto", cascade="all, delete-orphan")
    tareas = relationship("Tarea", back_populates="proyecto", cascade="all, delete-orphan")
    
# ------

class EstadoTarea(enum.Enum):
    sin_asignar = "sin_asignar"
    pendiente = "pendiente"
    en_progreso = "en_progreso"
    completado = "completado"

class Tarea(Base):
    __tablename__ = "tareas"

    id = Column(Integer, primary_key=True, index=True)
    id_proyecto = Column(Integer, ForeignKey("proyectos.id", ondelete="CASCADE"), nullable=False)
    titulo = Column(String(100), nullable=False)
    descripcion = Column(Text)
    estado = Column(Enum(EstadoTarea), default=EstadoTarea.pendiente)
    fecha_creacion = Column(DateTime, default=datetime.now)
    fecha_limite = Column(DateTime)

    # Relaciones
    proyecto = relationship("Proyecto", back_populates="tareas")
    responsables = relationship("TareaResponsable", back_populates="tarea", cascade="all, delete-orphan")
    
# ------  
    
class TareaResponsable(Base):
    __tablename__ = "TareaResponsables"

    id = Column(Integer, primary_key=True, index=True)
    id_tarea = Column(Integer, ForeignKey("tareas.id", ondelete="CASCADE"))
    id_usuario = Column(Integer, ForeignKey("usuarios.id", ondelete="CASCADE"))

    tarea = relationship("Tarea", back_populates="responsables")
    usuario = relationship("Usuario", back_populates="tareas_asignadas")
    
# ------
    
class RolProyecto(enum.Enum):
    dueño = "dueño"
    editor = "editor"
    lector = "lector"

class ProyectoIntegrante(Base):
    __tablename__ = "ProyectoIntegrantes"

    id = Column(Integer, primary_key=True, index=True)
    id_proyecto = Column(Integer, ForeignKey("proyectos.id", ondelete="CASCADE"))
    id_usuario = Column(Integer, ForeignKey("usuarios.id", ondelete="CASCADE"))
    rol = Column(Enum(RolProyecto), nullable=False)

    # Relaciones
    proyecto = relationship("Proyecto", back_populates="integrantes")
    usuario = relationship("Usuario", back_populates="proyectos_integrante")