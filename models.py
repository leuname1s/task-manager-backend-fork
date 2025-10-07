from sqlalchemy import Column, Integer, String
from db import Base

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, autoincrement=True)
    correo = Column(String(120), unique=True, nullable=False)
    nombre = Column(String(100), nullable=False)
    contrasena = Column(String(200), nullable=False)

    def __repr__(self):
        return f"<Usuario(id={self.id}, correo='{self.correo}', nombre='{self.nombre}')>"
