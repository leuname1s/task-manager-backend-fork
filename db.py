from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os


# URL de conexión 

# USER = os.getenv("POSTGRESQL_USER")
# PASSWORD = os.getenv("POSTGRESQL_PASS") 
# DATABASE_URL = f"postgresql+psycopg2://{USER}:{PASSWORD}@localhost:5432/taskmanager"

DATABASE_URL = os.getenv("SUPABASE_DB_URL")

# Motor de conexión
engine = create_engine(DATABASE_URL, echo=True)

# Base para heredar en modelos
Base = declarative_base()

# Sesión
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# SessionLocal().close()