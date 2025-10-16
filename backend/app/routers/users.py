from fastapi import APIRouter, Depends
from app.database.models import User
from app.auth.dependencies import get_current_active_user

router = APIRouter()

@router.get("/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user
