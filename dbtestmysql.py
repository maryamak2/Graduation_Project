from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
URL_db="mysql+pymysql://root:MAK2025@localhost:3306/blog_db"

engine=create_engine(URL_db)

SessionLocal=sessionmaker(bind=engine,autoflush=False)

Base=declarative_base()