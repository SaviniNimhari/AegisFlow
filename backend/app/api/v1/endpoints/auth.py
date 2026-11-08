from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import get_current_active_user
from backend.app.core.security import create_access_token
from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.schemas.user import TokenResponse, UserCreate, UserLogin, UserResponse
from backend.app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new platform user"
)
def register(
    user_in: UserCreate,
    db: Session = Depends(get_db)
):
    """Register a new user account with Argon2 password hashing."""
    if AuthService.get_by_email(db, user_in.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists."
        )
    if AuthService.get_by_username(db, user_in.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this username already exists."
        )

    user = AuthService.create_user(db, user_in)
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user and issue JWT access token"
)
def login(
    login_data: UserLogin,
    db: Session = Depends(get_db)
):
    """Authenticate with username/email and password, returning a JWT bearer token."""
    user, error_msg = AuthService.authenticate_user(
        db,
        username_or_email=login_data.username_or_email,
        password=login_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_msg or "Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(subject=user.id, role=user.role)
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/token",
    summary="OAuth2 compatible token endpoint for Swagger UI"
)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """OAuth2 password flow compatible endpoint (used by Swagger /docs 'Authorize' button)."""
    user, error_msg = AuthService.authenticate_user(
        db,
        username_or_email=form_data.username,
        password=form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_msg or "Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(subject=user.id, role=user.role)
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile"
)
def get_current_user_profile(
    current_user: User = Depends(get_current_active_user)
):
    """Retrieve profile and RBAC role for the currently authenticated user."""
    return current_user
