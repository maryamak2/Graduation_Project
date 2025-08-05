from fastapi import HTTPException ,Depends ,status, Body,Form,APIRouter
from pydantic import BaseModel
from typing import Annotated
from dbtestmysql import SessionLocal
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
from modelsmysql import auth # Import models needed
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
import bcrypt
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os,base64
import base64  
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

Session_Management_router = APIRouter(
    tags=["Session Management"]  # Optional OpenAPI tag
)
# logstash_url = "http://127.0.0.1:5044"
logstash_url = "http://100.69.247.53:5044"


def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency=Annotated[Session,Depends(get_db)]


# Secret key and algorithm for JWT
SECRET_KEY = "ZTA-system-secret-key"  # Should be Replaced with a strong secret key in production
ALGORITHM = "HS256" #Algorithm used in JWT signature
ACCESS_TOKEN_EXPIRE_MINUTES = 1 # Increased for better user experience and less server overloadidng 
REFRESH_TOKEN_EXPIRE_MINUTES = 1 # Increased for better user experience and less server overloadidng 
key_session = os.urandom(32)  # 256-bit key

'''
OAuth2 scheme for token authentication
This is responsible for defining the API at which the token will be created and given to the user
directly after authentication
This creates a dependency that automatically:
1)Checks incoming requests for an "Authorization: Bearer <token>" header
2)Extracts the token for use in several API endpoints
3)Returns HTTP 401 if no valid token is present
Noting that:it only handles token extraction while real token validation is implemented separately in:
get_current_userFunction
'''

oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/auth/login")


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    user_id: int  
    email: str    
    role: str     
    session_auth: str  
    access_token_expires: int  
    refresh_token_expires: int  
    user_info: str  
    
class RefreshTokenRequest(BaseModel):
    access_token: str
    refresh_token: str
    current_location: str
    os: Optional[str] = None
    browser: Optional[str] = None

#This function checks for the entered email and password 1 Factor authentication:
#Noting that the function depends on comparing user entered credentials and this user credentials stored in the db
def authenticate_user(email: str, password: str, db):
    user = db.query(auth).filter(auth.Email == email).first()
    if not user:
        return False #There is no user ind db with this username
    #This is a function compares the hased version of the entered password and the stored hashed password
    if not bcrypt.checkpw(password.encode('utf-8'), user.Password.encode('utf-8')):
        return False #The entered password is incorrect and they didn't match
    return user #Success and the Email and password matches


# In-memory revoked tokens set (for short-lived tokens -> RAM storage)
REVOKED_TOKENS = set()




'''
get_current_user Function:
This function is responsible for getting the current user who try to access an API endpoint by passing the 
backend server his access token which he uses and this is sufficient to check whether this user is authorized
1st the toekn is checked if it is in the revoked tokens list
2nd Integrity check is done to verify the payload integrity and ensure that this token was originally produced 
by this server, Then if everything is valid the returned parameters necessary to identify this user is returned
to be used by any API to define which user is accessing and requesting the system web services
'''
async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        # First check if token is revoked if revoked then this is an invalid token
        if token in REVOKED_TOKENS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )

        #This line is responsible for checking integrity as well as decoding the access token as:
        #an exception "jwt.exceptions.InvalidSignatureError" will be raised if the signature is invalid 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        #Checking that the user is accessing an API using his access token not the refresh token:
        if payload.get('type') != 'access':
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token type')
        email: str = payload.get('sub')
        user_id: int = payload.get('id')
        role: str = payload.get('role')
        user_info: str = payload.get('user_info')  # Extract concatenated user info from the token payload
        if email is None or user_id is None or role is None or user_info is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user')
        return {'email': email, 'user_id': user_id, 'role': role, 'user_info': user_info ,'token':token}
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f'Could not validate user: {str(e)}')


''''
This function is responsible for the Token creation and notice that returned value includes the credentials which
will be an authorized token form due to including the secret key of the server
'''
def create_token(email: str, user_id: int, role: str, expires_delta: timedelta, token_type: str, user_info: str):
    encode = {
        'sub': email,
        'id': user_id,
        'role': role,
        'type': token_type,
        'exp': datetime.utcnow() + expires_delta, #This is the time at which the token will expire
        'user_info': user_info  # Ensure this is a string or JSON-serializable object
    }
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM) #Algorithm and secretkey are passed to create the signature


class BanRequest(BaseModel):
    user_username:str
    ban_minutes: int = 5  # Default 15 minute ban
   
'''
This API is responsible for banning the user by taking his ID and storing the time at which this banned user
will be unbanned in the Banned until value corresponding in the auth table cloumn 
'''
@Session_Management_router.post("/ban-user/", status_code=status.HTTP_200_OK)
async def ban_user(
    ban_request: BanRequest,
    db: Session = Depends(get_db)  # Assuming you have a get_db dependency
):
    # Find the user
    user = db.query(auth).filter(auth.Email == ban_request.user_username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Calculate ban expiration time
    ban_duration = timedelta(minutes=ban_request.ban_minutes)
    user.banned_until = datetime.now() + ban_duration
    
    
    try:
        db.commit()
        return {
            "status": "success",
            "user_id": user.User_ID,
            "banned_until": user.banned_until,
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ban user: {str(e)}"
        )    
          

#This function responsible for TOKEN REVOKATION:
async def revoke_token(token: str = Depends(oauth2_bearer)):
    #Revokes the current user's token by adding it to the blocklist configured above
    REVOKED_TOKENS.add(token)  # Add to in-memory set (List)
    return {"message": "Token revoked successfully"}



'''
This is the main function for authentication and deciding whether this user is qualified to be given an access token 
or not, If user is authenticated it haves the whole row in the auth table corresponding to the user and according to it:
1)Checks if user entered credentials are valid
2)Checks whether this user is banned or not
3)Logs the user login to logstach
4)Gets the user info and encrypts it to be ready to be included in token payload
5)Handles the expiary time of access and refresh token as configured above
'''

@Session_Management_router .post("/auth/login", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], #OAuth form submission of user credentials to protect them in transit
    db: db_dependency,
    #When a user login he submits his current info with the login credentials
    current_location: str = Form(...),
    os: Optional[str] = Form(None),
    browser: Optional[str] = Form(None)
):
    #Function checks the user credentials and return the corresponding row in auth table is user is authenticated
    user = authenticate_user(form_data.username, form_data.password, db)
#    user = verify_user_credentials(form_data.username, form_data.password, db)

    
    #If the authentiacte_user function fails to authenticate the user according to his entered credentials
    #Logs are issued and HTTP exception is returned
    if not user:
        user_info1 = {
            "username": form_data.username,
            "location": current_location,
            "os": os,
            "browser": browser,
            "status" : 'FailedLogin' }
        requests.post(logstash_url, json=user_info1)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Couldn't validate this user")
    
    
    # Check if user is banned as this check is done by checking the banned_until column in auth table user row
 #   if user.banned_until and user.banned_until > datetime.now():
  #      remaining_time = user.banned_until - datetime.now()
   #     remaining_minutes = int(remaining_time.total_seconds() / 60)
        
    #    raise HTTPException(
     #       status_code=status.HTTP_403_FORBIDDEN,
      #      detail=f"Account is temporarily banned. Try again in {remaining_minutes} minutes."
       # )
    
    # Send data to Logstash
    # Prepare data for Logstash
    user_info = {
        "username": form_data.username,
        "location": current_location,
        "os": os,
        "browser": browser,
        "email": user.Email,
        "user_id": user.User_ID,
        "Role": user.Role,
        "status": "SUCCESSFUL",
        "Service":"Access Token"
    }

    
    requests.post(logstash_url, json=user_info)

    # Concatenate loc, os, and browser into a single string to prepare to be put in the user_info part of token payload
    user_info_before_encryption = f"loc: {current_location}, os: {os}, browser: {browser}"
    
    # Encrypt the user info 
    encrypted_user_info = encrypt_user_info(key_session, user_info_before_encryption)
    user_info = base64.b64encode(encrypted_user_info).decode('utf-8')  # Encode to Base64 and decode to string
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    
    access_token = create_token(user.Email, user.User_ID, user.Role, access_token_expires, "access", user_info)
    refresh_token = create_token(user.Email, user.User_ID, user.Role, refresh_token_expires, "refresh", user_info)
    
    # Decode tokens to get expiry time
    access_token_payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
    refresh_token_payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    
    print(user_info) #To visualize server handling of tokens 
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer',
        'user_id': user.User_ID,
        'email': user.Email,
        'role': user.Role,
        'session_auth': 'active',  # Populate this field
        #Expiry times are returned to front end to be able to handle tokens timing successfully
        'access_token_expires': int(access_token_payload['exp']),   
        'refresh_token_expires': int(refresh_token_payload['exp']),   
        'user_info': user_info  # Include Base64-encoded user info in the response
    }
    
    
'''
This is one of the most imortant APIs in the entire project!
The API is used when the user requires to refresh his access token which means extending the session
1)Takes user current ifo and validations from the access token he currently uses
2)Ensure that this is an access token
3)Check that the token is valid and didn't expire
4)Prevents overloading server by unneccessary too much tokens by checking the expiry time 
5)Decrypts the user current info part in the payload to use it in validating the user
6)Compares the user info user reported to the API when requested issuing a refresh token and the user info
was included in the access token he uses and wants to refresh , if these parameters are acceptable making sense
the server will proceed to give this user an access token and extend the session successfully

'''
@Session_Management_router .post("/auth/refresh")
async def refresh_access_token(db: db_dependency, request: RefreshTokenRequest = Body(...)):
    try:
        print(f"Incoming request: {request}")  # Log the incoming request
        accesst=request.access_token   #gets the access token whose parameters will be users's old info and this is used to determine the old access token expiry time
        user=get_current_user(accesst) #To know user is accessing this API 
        # Decode the refresh token and check integrity
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Decoded payload: {payload}")  # Log the decoded payload on the server console

        # Check if the token is a refresh token
        if payload.get('type') != 'refresh':
            user_info = {
                "status": "FAILED",
                "Service":"Refresh Token"
            }
            requests.post(logstash_url, json=user_info)
            print("Invalid token type: expected 'refresh'")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token type')

        # Extract user details from the token
        email: str = payload.get('sub')
        user_id: int = payload.get('id')
        role: str = payload.get('role')
        old_user_info_b64: str = payload.get('user_info')  # Extract Base-64 encoded encrypted user info from the token payload

        # Check if the token has expired
        if datetime.utcnow() > datetime.fromtimestamp(payload.get('exp')):
            print("Refresh token has expired")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Refresh token has expired')
        
        
        # Time left before token expires
        current_time_utc = datetime.utcnow()
        current_time_egypt = current_time_utc + timedelta(hours=3)  # UTC+3 (Egypt Time)

        time_remaining =  -(current_time_egypt-datetime.fromtimestamp(payload.get('exp')) )
        
        #This section to prevent the DOS or overloading the Server by the refresh requests
        # Check if more than (1/1.5 ≈ 60%) of the lifetime remains
        if (time_remaining > timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES / 1.5)) and (time_remaining > timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES / 1.5)):
            print("Refresh token overload")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Refresh token overload')

        # Decode Base64 to bytes
        old_user_info_encrypted = base64.b64decode(old_user_info_b64.encode('utf-8'))  # Convert Base64 string to bytes

        # Decrypt the user info
        old_user_info = decrypt_user_info(key_session, old_user_info_encrypted)  # Pass bytes to decrypt_message
        
        # Validate the all user details exists
        if email is None or user_id is None or role is None or old_user_info is None:
            print("Missing required fields in token payload")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user')

        #Fetch the user from the database this section isnot done to achive statelessness as the token wont be 
        #originally produced by the server unless the user was basically authenticated
        # user = db.query(auth).filter(auth.Email == email).first()
        # if not user:
        #     print("User not found in database")
        #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User not found')

        # Extract old location from user_info
        try:
            old_loc_part = old_user_info.split(", ")[0]  # Extract "loc: 30.06024,30.961143"
            if not old_loc_part.startswith("loc: ") or "," not in old_loc_part:
                raise ValueError("Invalid location format in old_user_info")

            # Extract latitude and longitude
            lat_lon = old_loc_part.split("loc: ")[1].split(",")
            if len(lat_lon) != 2:
                raise ValueError("Invalid location format in old_user_info")

            old_lat = float(lat_lon[0])
            old_lon = float(lat_lon[1])
        except (IndexError, ValueError) as e:
            print(f"Error parsing old location: {e}")  # Log the error
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid location format in refresh token: {e}")

        # Extract new location from the request body
        try:
            lat_lon = request.current_location.split(",")
            if len(lat_lon) != 2:
                raise ValueError("Invalid location format in request")

            new_lat = float(lat_lon[0])
            new_lon = float(lat_lon[1])
        except (IndexError, ValueError) as e:
            print(f"Error parsing new location: {e}")  # Log the error
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid location format in request: {e}")

        # Calculate the distance between the old and new locations
        distance = haversine(old_lat, old_lon, new_lat, new_lon)
        print(f"Distance between old and new location: {distance} km")

        # Check if the new location is within 10 km of the old location
        if distance > 10.0:  # 10 km threshold
            print("Location mismatch: new location is more than 10 km away")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid refresh token: location mismatch')

        # Concatenate new loc, os, and browser into a single string to be put in new token payload
        new_user_info = f"loc: {request.current_location}, os: {request.os}, browser: {request.browser}"

        # Compare old and new user_info (excluding location as it was done above)
        old_user_info_without_loc = ", ".join(old_user_info.split(", ")[1:])  # Remove location part
        new_user_info_without_loc = ", ".join(new_user_info.split(", ")[1:])  # Remove location part
        print(f"Old user info without location: {old_user_info_without_loc}")
        print(f"New user info without location: {new_user_info_without_loc}")

        if old_user_info_without_loc != new_user_info_without_loc:
            print("User info mismatch")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid refresh token: user info mismatch')

        # If location and user_info match, proceed with creating new tokens
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)

        # Encrypt the new user info and encode it using Base64
        new_user_info_encrypted = encrypt_user_info(key_session, new_user_info)  # Pass the string directly
        new_user_info_b64 = base64.b64encode(new_user_info_encrypted).decode('utf-8')  # Encode to Base64 and decode to string

        access_token = create_token(email, user_id, role, access_token_expires, "access", new_user_info_b64)
        refresh_token = create_token(email, user_id, role,  refresh_token_expires, "refresh", new_user_info_b64)

        # Decode tokens to get expiry time
        access_token_payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        refresh_token_payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Prepare data for Logstash
        user_info = {
            "username": email,
            "location": request.current_location,
            "os": request.os,
            "browser": request.browser,
            "email": email,
            "user_id": user_id,
            "Role": role,
            "status": "SUCCESSFUL",
            "Service":"Refresh Token"
        }
        # Send data to Logstash
        requests.post(logstash_url, json=user_info)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer',
            'user_id': user_id,
            'email': email,
            'role': role,
            'session_auth': 'active',  # Populate this field
            'access_token_expires': int(access_token_payload['exp']),  # Convert to timestamp
            'refresh_token_expires': int(refresh_token_payload['exp']),  # Convert to timestamp
            'user_info': new_user_info_b64  # Include Base64-encoded user info in the response
        }
    except jwt.ExpiredSignatureError:
        print("Refresh token has expired")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Refresh token has expired. Please log in again.')
    except JWTError as e:
        print(f"JWTError: {e}")  # Log the JWTError
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f'Could not validate user: {str(e)}')
    except Exception as e:
        print(f"Unexpected error: {e}")  # Log any unexpected errors
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f'An error occurred: {str(e)}')


#Function to calculate the distance between 2 geolocations in Km
#The passed 2 geolocations are the old and new locations of the user to get distance between them
def haversine(lat1, lon1, lat2, lon2):
    
    #Calculate the great-circle distance between two points on the Earth (specified in decimal degrees).
    #Returns the distance in kilometers.
    
    # Converting decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula:
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    
    # Radius of Earth in kilometers
    R = 6371.0
    distance = R * c
    return distance

#The follwoing approach of encryption depends on changing the KEY periodically!

# Encrypt a message using AES-256 
# This function is user to encrypt the user info in the JWT 
def encrypt_user_info(key, plaintext):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.ECB(), #The traditional AES without modifications
        backend=default_backend()
    ).encryptor()

    # Pad the plaintext to be a multiple of 16 bytes which is the AES block size
    pad_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext.encode('utf-8') + bytes([pad_length] * pad_length)

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

# Decrypt a message using AES-256
# This function is user to decrypt the user info in the JWT 
def decrypt_user_info(key, ciphertext):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.ECB(), #The traditional AES without modifications
        backend=default_backend()
    ).decryptor()

    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding done in the encrypt function
    pad_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_length]
    return plaintext.decode('utf-8')


##AES-GCM encryption used for tokens as an alternative 
##but we'll take into consideration the IV will be stored in the token structure!!
# # Derive a fixed IV from the key
# def derive_iv(key):
#     hkdf = HKDF(
#         algorithm=hashes.SHA256(),
#         length=12,  # 96-bit IV for AES-GCM
#         salt=None,
#         info=b"fixed-iv which needs to be randomized",
#     )
#     return hkdf.derive(key)



# # Encrypt a message (deterministic)
# def encrypt_user_info(key, plaintext):
#     # Derive a fixed IV from the key
#     iv = derive_iv(key)

#     # Construct an AES-GCM Cipher object with the given key and fixed IV
#     encryptor = Cipher(
#         algorithms.AES(key),
#         modes.GCM(iv)
#     ).encryptor()

#     # Encrypt the plaintext and get the associated ciphertext
#     ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

#     # Return the ciphertext and tag
#     return ciphertext + encryptor.tag

# # Decrypt a message (deterministic)
# def decrypt_user_info(key, ciphertext_with_tag):
#     # Derive the fixed IV from the key
#     iv = derive_iv(key)

#     # Split the ciphertext and tag
#     ciphertext = ciphertext_with_tag[:-16]  # Last 16 bytes are the tag
#     tag = ciphertext_with_tag[-16:]

#     # Construct an AES-GCM Cipher object with the given key, fixed IV, and tag
#     decryptor = Cipher(
#         algorithms.AES(key),
#         modes.GCM(iv, tag)
#     ).decryptor()

#     # Decrypt the ciphertext and get the associated plaintext
#     plaintext = decryptor.update(ciphertext) + decryptor.finalize()

#     # Return the decrypted plaintext
#     return plaintext.decode()
