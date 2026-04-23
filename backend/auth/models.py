from pydantic import BaseModel, Field


class AuthRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: int
    username: str
    created_at: str
    is_admin: bool


class UserInDB(UserResponse):
    hashed_password: str


class TokenData(BaseModel):
    username: str
