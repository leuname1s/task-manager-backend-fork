from pydantic import BaseModel, ConfigDict, RootModel
from typing import Optional, Literal, Dict, List
from datetime import datetime
from models import EstadoTarea
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
    
    id: int
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
    
class TareaCreate(BaseModel):
    titulo: str
    descripcion: Optional[str] = None
    fecha_limite: Optional[datetime] = None

class ResponsableResumen(BaseModel):
    model_config = ConfigDict(from_attributes=True)
        
    id: int
    nombre: str

class TareaResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    id_proyecto: int
    titulo: str
    descripcion: Optional[str] = None
    estado: str
    fecha_creacion: datetime
    fecha_limite: Optional[datetime] = None
    responsables: Optional[List[ResponsableResumen]]

class ResponsablesAddRequest(BaseModel):
    correos: List[str]
    
class TareaEstadoUpdate(BaseModel):
    estado: EstadoTarea