"""Authentication endpoints"""
from fastapi import APIRouter, HTTPException, status
from datetime import timedelta

from app.models.schemas import UserCreate, Token, User
from app.core.auth import (
    authenticate_user,
    create_access_token,
    create_user,
    get_current_active_user
)
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/register")
async def register(user_data: UserCreate):
    """Register a new user"""
    try:
        create_user(user_data.username, user_data.password)
        return {"message": f"User {user_data.username} created successfully"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post("/token", response_model=Token)
async def login(username: str, password: str):
    """Login and get JWT token"""
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=User)
async def read_users_me(current_user: User = get_current_active_user):
    """Get current user information"""
    return current_user
