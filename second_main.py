from fastapi import FastAPI, HTTPException, Depends, status, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
# Initialize FastAPI app
app = FastAPI()
import uvicorn
# Secret key for JWT encoding
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 1 day
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
# Context for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Mock database
fake_users_db = {
    "asd": {
        "username": "asd",
        "full_name": "John Doe",
        "hashed_password": pwd_context.hash("asd"),
        "disabled": False,
    }
}

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# Pydantic models for request and response
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(db, username: str):
    print(username)
    user = db.get(username)
    if user:
        return UserInDB(**user)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: LoginRequest):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/logout")
async def logout(response: Response):
    # This is more of a placeholder since we're using JWT tokens. You would "log out" by having the client delete the token.
    response.delete_cookie("Authorization", path="/")
    return {"message": "Logged out"}


@app.get("/session")
async def get_session(current_user: User = Depends(get_current_active_user)):
    return {"user": current_user.username}

if __name__ == '__main__':
    uvicorn.run(app, host= 'localhost', port=5000)