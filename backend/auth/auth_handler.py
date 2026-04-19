import os
import sqlite3
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from auth.models import TokenData, UserInDB


# Default to a development secret, but allow secure overrides in deployment.
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
DATABASE_PATH = os.path.join(os.path.dirname(__file__), "auth.db")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_auth_db() -> None:
    """Create the user table once during app startup."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.commit()


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_user(username: str, password: str) -> UserInDB:
    hashed_password = hash_password(password)
    created_at = datetime.now(timezone.utc).isoformat()

    try:
        with get_connection() as connection:
            cursor = connection.execute(
                "INSERT INTO users (username, hashed_password, created_at) VALUES (?, ?, ?)",
                (username, hashed_password, created_at),
            )
            connection.commit()
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists.",
        ) from exc

    return UserInDB(
        id=user_id,
        username=username,
        hashed_password=hashed_password,
        created_at=created_at,
    )


def get_user_by_username(username: str) -> UserInDB | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, username, hashed_password, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if row is None:
        return None

    return UserInDB(
        id=row["id"],
        username=row["username"],
        hashed_password=row["hashed_password"],
        created_at=row["created_at"],
    )


def authenticate_user(username: str, password: str) -> UserInDB:
    user = get_user_by_username(username)
    if user is None or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenData(username=username)


def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    token_data = decode_access_token(token)
    user = get_user_by_username(token_data.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
