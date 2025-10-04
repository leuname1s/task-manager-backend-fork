from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

USER = os.getenv("POSTGRESQL_USER")
PASSWORD = os.getenv("POSTGRESQL_PASS") 
# URL de conexión 
DATABASE_URL = f"postgresql+psycopg2://{USER}:{PASSWORD}@localhost:5432/taskmanager"
# Motor de conexión
engine = create_engine(DATABASE_URL, echo=True)

# Base para heredar en modelos
Base = declarative_base()

# Sesión
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# SessionLocal().close()