from fastapi import APIRouter, status

from auth.auth_handler import authenticate_user, create_access_token, create_user
from auth.models import AuthRequest, TokenResponse, UserResponse


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: AuthRequest) -> UserResponse:
    """Register a new user with a bcrypt-hashed password."""
    user = create_user(payload.username, payload.password)
    return UserResponse(
        id=user.id,
        username=user.username,
        created_at=user.created_at,
        is_admin=user.is_admin,
    )


@router.post("/login", response_model=TokenResponse)
def login_user(payload: AuthRequest) -> TokenResponse:
    """Validate credentials and return a JWT bearer token."""
    user = authenticate_user(payload.username, payload.password)
    access_token = create_access_token(subject=user.username)
    return TokenResponse(access_token=access_token)
