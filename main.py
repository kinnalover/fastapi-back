import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

from pip._internal.network import session
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
# Define a secret key for JWT (in a real app, this should be securely stored)
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 300

app = FastAPI()
import util
import config
# In-memory storage for invalidated tokens (for demonstration purposes)
invalidated_tokens = set()
origins = [
    "http://localhost:5173",  # Replace with the URL of your SvelteKit application
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginRequest(BaseModel):
    username: str
    password: str

# Your LDAP authentication function (already implemented)
def ldap_auth(username: str, password: str) -> bool:
    # Perform LDAP authentication
    # Return True if successful, False otherwise
    # ldap = util.LDAP(config.hq_ldap_host,
    #                  config.hq_ldap_user,
    #                  config.hq_ldap_password,
    #                  config.hq_ldap_search_base,
    #                  config.hq_ldap_attributes,
    #                  config.hq_ldap_groups)
    #
    #
    # account_info = ldap.account_info(username, skip_member_check=True)
    # if account_info is not None:
    #     if not ldap.check_password(account_info['distinguishedName'], password):
    #         return False
    #
    #     return True
    if username =='00057486':
        return True
    return False



# Function to create JWT tokens
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Dependency to verify JWT tokens
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if token in invalidated_tokens:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been invalidated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Login endpoint
@app.post("/login")
async def login(form_data: LoginRequest):
    username = form_data.username
    password = form_data.password

    print(username)

    # Authenticate with LDAP
    if not ldap_auth(username, password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Generate JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    session_store.update({access_token: {"session": access_token, "username": username}})
    print(session_store)
    return {"access_token": access_token, "token_type": "bearer"}


# Logout endpoint
@app.post("/logout")
async def logout(token: str = Depends(verify_token)):
    # Invalidate the token
    invalidated_tokens.add(token)
    session_store.__delitem__(token)
    return {"message": "Successfully logged out"}

session_store = {
    "session_12345": {"session": 1, "username": "testuser"},
    # Add more sessions as needed
}
@app.get("/session")
async def get_session(request: Request):
    session_id = request.headers.get("Cookie")
    print(f'session_id {session_id}')
    if not session_id:
        # If the cookie is not present, return a 400 Bad Request error
        raise HTTPException(status_code=400, detail="Session ID is missing")

    # Fetch session details from the session store
    session_data = session_store.get(session_id)

    if not session_data:
        # If the session is not found, return a 401 Unauthorized error
        raise HTTPException(status_code=401, detail="Invalid session")

    # If session is valid, return session data
    return JSONResponse(content=session_data)


if __name__ == '__main__':
    uvicorn.run(app, host= 'localhost', port=5000)