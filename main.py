from fastapi import FastAPI ,HTTPException ,Depends ,status, Request,Body,Form, Response
from pydantic import BaseModel
from typing import Annotated
import modelsmysql
from dbtestmysql import engine,SessionLocal
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List,Optional
from modelsmysql import Patient,auth, Billing, Doctors,Clinical_services,Nurses # Import models from external file
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import random,os, uvicorn
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
import math,uuid
#from user_agents import parse  # Add the user_agents library for parsing the User-Agent
#from jose import jwt, JWTError, ExpiredSignatureError
import bcrypt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os,base64
import Identity_Management,Patient_record_Server,Session_Management

    

app= FastAPI()
security = HTTPBearer()
modelsmysql.Base.metadata.create_all(bind=engine)
app.include_router(Identity_Management.IM_router)
app.include_router(Patient_record_Server.Patient_record_router)
app.include_router(Session_Management.Session_Management_router)



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency=Annotated[Session,Depends(get_db)]

