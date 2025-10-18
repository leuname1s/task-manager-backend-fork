from pydantic import BaseModel, ConfigDict, RootModel
from typing import Optional, Literal, Dict
from datetime import datetime
# Para registro de usuario
class UserCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    correo: str
    nombre: str
    contraseña: str

# Para login
class UserLogin(BaseModel):
    correo: str
    contraseña: str

class CaptchaRequest(BaseModel):
    token: str
    
class ResetPasswordRequest(BaseModel):
    correo: str
    token: Optional[str]
    nueva_contraseña: str
    
class ProyectoCreate(BaseModel):
    nombre: str
    descripcion: Optional[str] = None

class ProyectoUsuarioInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    nombre_proyecto: str
    descripcion: Optional[str] = None
    fecha_finalizacion: Optional[datetime] = None
    rol_usuario: str
    
class IntegrantesAddRequest(RootModel):
    root:Dict[str, Literal["editor", "lector"]]
    model_config = {
        "json_schema_extra": {"examples": [
                {
                    "test@gmail.com":"editor",
                    "jose@gmail.com":"lector",
                    "perez@gmail.com":"editor"
                }]}
}
    
class IntegranteRemoveRequest(BaseModel):
    correo: str