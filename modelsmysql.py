from dbtestmysql import Base,engine
from sqlalchemy import Double,Column,Integer,String ,ForeignKey,Boolean,BigInteger,TIMESTAMP, DateTime
from sqlalchemy.orm import relationship
from pydantic import BaseModel
from typing import Optional



'''
class Activity(Base):
    __tablename__ = "activity_check"
    User_ID = Column(Integer, primary_key=True, index=True)
    Location = Column(Integer)
    Working_Hours_Violation = Column(String(250))
    Last_Login_Date= Column(String(250))
'''

  #hi  

class Doctors(Base):
    __tablename__ = "doctors"
    
    Doctor_ID = Column(Integer, primary_key=True, index=True)
    Department_ID = Column(Integer)
    Contact = Column(String(250))
    Available_Hours = Column(String(250))
    Department_Name = Column(String(250))
    
    # Relationship to Patient (one-to-many: one doctor can have many patients)
    patients_with_nurse = relationship("Patient", back_populates="prescribing_doctor")


class AuthResponse(BaseModel):
    User_ID: int
    Username: str
    Email: str
    Role: str
    # Include only the fields you want to return
    
    class Config:
        orm_mode = True


class auth(Base):
    __tablename__ = "authentication"
    User_ID = Column(Integer, primary_key=True, index=True)
    Username= Column(String(250))
    Password= Column(String(250))
    National_ID=Column(BigInteger)
    Full_Name= Column(String(250))
    Email= Column(String(250))
    Role= Column(String(250))
    Last_Login_Date= Column(String(250))
    Activity_Logs= Column(String(250))
    banned_until = Column(TIMESTAMP, nullable=True)
    
    class Config:
        from_attributes = True

    
class Nurses(Base):
    __tablename__ = "nurses"
    Nurse_ID = Column(Integer, primary_key=True, index=True)
    Department_ID=Column(Integer)
    Department_Name= Column(String(250))
    Contact= Column(String(250))
    Shift_Hours= Column(String(250))
    
    patients_with_nurse = relationship("Patient", back_populates="prescribing_nurse")
    
    
class Clinical_services(Base):
    __tablename__ = "clinical_services_modified"
    
    Patient_ID = Column(Integer, ForeignKey('patients_with_nurse.User_ID'), primary_key=True, index=True)
    Department_ID = Column(Integer)
    Medication_Name = Column(String(250))
    Dosage_Instructions = Column(String(250))
    Responsible_Doctor_ID = Column(Integer)
    Treatment_Details = Column(String(250))
    Department_Name = Column(String(250))
    
    # Relationship to Patient (many-to-one)
    patient = relationship("Patient", back_populates="clinical_services")


class Patient(Base):
    __tablename__ = "patients_with_nurse"
    
    User_ID = Column(Integer, primary_key=True, index=True) #
    Patient_ID_Clinical = Column(Integer)
    Patient_ID_Billing = Column(Integer)
    Gender = Column(String(250)) #
    Contact = Column(String(250))
    Allergies = Column(String(250))
    Chronic_Conditions = Column(String(250))
    Purpose_of_Visit = Column(String(250))
    Prescribing_Doctor_ID = Column(Integer, ForeignKey('doctors.Doctor_ID')) #
    Prescribing_Nurse_ID = Column(Integer, ForeignKey('nurses.Nurse_ID')) #
    
    # Relationship to Billing (one-to-one)
    billing = relationship("Billing", back_populates="patient", uselist=False)
    
    # Relationship to Doctors (many-to-one)
    prescribing_doctor = relationship("Doctors", back_populates="patients_with_nurse")

    # Relationship to Nurses (many-to-one)
    prescribing_nurse = relationship("Nurses", back_populates="patients_with_nurse")

    
    # Relationship to Clinical_services (one-to-many)
    clinical_services = relationship("Clinical_services", back_populates="patient")


class PatientUpdate(BaseModel):
    Patient_ID_Clinical: Optional[int] = None
    Patient_ID_Billing: Optional[int] = None
    Gender: Optional[str] = None
    Contact: Optional[str] = None
    Allergies: Optional[str] = None
    Chronic_Conditions: Optional[str] = None
    Purpose_of_Visit: Optional[str] = None
    Prescribing_Doctor_ID: Optional[int] = None
    Prescribing_Nurse_ID: Optional[int] = None

    class Config:
        orm_mode = True


class Billing(Base):
    __tablename__ = "billing and finance (4)"
    
    Patient_ID = Column(Integer, ForeignKey('patients_with_nurse.User_ID'), primary_key=True, index=True)
    Status = Column(String(250))
    Payment_Mode = Column(String(250))
    Amount_Paid = Column(Double)
    
    # Relationship to Patient
    patient = relationship("Patient", back_populates="billing")
    
    
