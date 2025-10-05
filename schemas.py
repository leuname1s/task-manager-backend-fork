from pydantic import BaseModel, ConfigDict

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
