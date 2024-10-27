from fastapi import APIRouter

from .auth.views import router as auth_router
from .users.views import router as users_router

router = APIRouter(prefix="/v1")

router.include_router(auth_router, prefix="/auth")
router.include_router(users_router, prefix="/users")
