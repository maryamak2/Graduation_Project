from fastapi import FastAPI ,HTTPException ,Depends ,status, Request,Body,Form,APIRouter
from pydantic import BaseModel
from typing import Annotated
import modelsmysql
from dbtestmysql import engine,SessionLocal
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import bcrypt, requests
from datetime import datetime, timedelta
from pydantic import BaseModel
from sqlalchemy.orm import Session


# logstash_url = "http://127.0.0.1:5044"
logstash_url = "http://100.69.247.53:5044"


def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency=Annotated[Session,Depends(get_db)]

IM_router = APIRouter(
    tags=["Identity Management"]  # Optional OpenAPI tag
)


class AuthBase(BaseModel):
    User_ID: int
    Username: str
    Password: str
    National_ID: int
    Full_Name: str
    Email: str
    Role: str
    Last_Login_Date: datetime  # Use datetime in Pydantic
    Activity_Logs: str

    class Config:
        orm_mode = True

@IM_router.post("/auth", status_code=status.HTTP_201_CREATED)
async def create_auth(auth_data: AuthBase, db: Session = Depends(get_db)):

    hashed_password = bcrypt.hashpw(auth_data.Password.encode('utf-8'), bcrypt.gensalt())
    auth_data.Password = hashed_password.decode('utf-8')  # Store the hashed password as a string
    db_auth = modelsmysql.auth(**auth_data.dict())
    # If role is 'Doctor'
    if db_auth.Role == 'Doctor':
        does_doctor_acc_exist = db.query(modelsmysql.auth).filter(modelsmysql.auth.Email == db_auth.Email).first()
        if does_doctor_acc_exist:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"There's already an account for doctor with email {db_auth.Email}"
            )
        else:
            db.add(db_auth)
            db.commit()
            db.refresh(db_auth)

        
        # Add doctor to the doctors table
            db_doctor = modelsmysql.Doctors(
            Doctor_ID=db_auth.User_ID,
            Department_ID=1,  # Placeholder
            Department_Name="Cardiology",  # Placeholder
            Contact="123-456-7890",  # Placeholder
            Available_Hours="9 AM - 5 PM",  # Placeholder
        )
            db.add(db_doctor)
            db.commit()
            db.refresh(db_doctor)
            return db_auth

    # If Role is 'Patient'
    does_patient_acc_exist = db.query(modelsmysql.auth).filter(modelsmysql.auth.User_ID == db_auth.User_ID).first()
    if does_patient_acc_exist:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"There's already an account for patient with id {db_auth.User_ID}"
        )

    does_patient_exist = db.query(modelsmysql.Patient).filter(modelsmysql.Patient.User_ID == db_auth.User_ID).first()
    if does_patient_exist:
        db.add(db_auth)
        db.commit()
        db.refresh(db_auth)
        return db_auth
    else:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail=f"There is no patient with id {db_auth.User_ID}"
        )

# Define request model for password reset
class ResetPasswordRequest(BaseModel):
    email: str
    newPassword: str


def verify_user_credentials(username: str, password: str, db: Session):
    user = db.query(modelsmysql.auth).filter(modelsmysql.auth.Email == username).first()
    if not user:
        return None
    if not bcrypt.checkpw(password.encode(), user.Password.encode()):
        return None
    return user


@IM_router.post("/auth/authenticate")
async def authenticate_user(db: db_dependency, credentials: dict = Body(...)):
    username = credentials.get("username")
    password = credentials.get("password")
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    
    
    user = verify_user_credentials(username, password, db)
    userdata = db.query(modelsmysql.auth).filter(modelsmysql.auth.Email == username).first()
    if not user:
        user_info1 = {
           # "username": userdata.Username,
            "Role": userdata.Role,
            "UserID": userdata.User_ID,
            "username": userdata.Email,
            "status" : 'FailedLogin' }
        requests.post(logstash_url, json=user_info1)
        raise HTTPException(status_code=401, detail="Invalid email")

    if not bcrypt.checkpw(password.encode(), user.Password.encode()):
        user_info1 = {
            "username": user.Full_Name,
            "Role": userdata.Role,
            "UserID": userdata.User_ID,
            "Email": user.Email,
            "status" : 'FailedLogin' }
        requests.post(logstash_url, json=user_info1)
        raise HTTPException(status_code=401, detail="Invalid password")
    
      # Check if user is banned
   # print(type(userdata.banned_until))  
    print(f"user banned until: {userdata.banned_until}")
   # print(datetime.now())
    if user.banned_until:
    # Convert string to datetime only if it's a string
        if isinstance(user.banned_until, str):
            banned_until_dt = datetime.strptime(user.banned_until, "%Y-%m-%d %H:%M:%S.%f")
        else:
            banned_until_dt = user.banned_until

        if banned_until_dt > datetime.now():
            remaining_time = banned_until_dt - datetime.now()
            remaining_minutes = int(remaining_time.total_seconds() / 60)

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is temporarily banned. Try again in {remaining_minutes} minutes."
        )

    
 
    
    return {  # Explicit JSON response
        "status": "success",
        "email": user.Email,
        "role": user.Role,  # Ensure this matches your frontend expectation
        "user_id": user.User_ID
    }



# Password Reset Route
@IM_router.post("/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)): # Query the user from the database):
    user = db.query(modelsmysql.auth).filter(modelsmysql.auth.Email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.Password = request.newPassword  
    user.Password = bcrypt.hashpw(user.Password.encode('utf-8'), bcrypt.gensalt())
    db.commit()

    if not bcrypt.checkpw(user.Password.encode('utf-8'), user.Password.encode('utf-8')):
        return False
    
    return {"message": "Password reset successful!"}


# Define check model for email check
class CheckEmailRequest(BaseModel):
    email: str
    
# Check Email Route
@IM_router.post("/check-email")
def check_email(request: CheckEmailRequest, db: Session = Depends(get_db)): # Query the user from the database):
    user = db.query(modelsmysql.auth).filter(modelsmysql.auth.Email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Please enter a valid email!")  # Explicit error message
    
    return {"message": "Email found! You can proceed with password reset."}

class OTPrequest(BaseModel):
    email:str


#API used to verify the OTP
@IM_router.post("/verify-otp")
def verify_otp(request: OTPrequest, db: Session = Depends(get_db)):
    user = db.query(modelsmysql.auth).filter(modelsmysql.auth.Email == request.email).first()
    user_info = {
        "username": user.Email,
        "email": user.Email,
        "user_id": user.User_ID,
        "Role": user.Role,
        "status" : 'ThreeFailedOTP'
        }
    requests.post(logstash_url, json=user_info)  