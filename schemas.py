from pydantic import BaseModel, ConfigDict
from typing import Optional

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