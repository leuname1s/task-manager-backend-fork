from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os


# URL de conexión 

load_dotenv()
DATABASE_URL = os.getenv("SUPABASE_DB_URL")

# Motor de conexión
engine = create_engine(DATABASE_URL, echo=True)

# Base para heredar en modelos
Base = declarative_base()

# Sesión
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
