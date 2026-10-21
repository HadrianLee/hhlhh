from fastapi import APIRouter

from identity.api.auth.router import router as auth_router
from identity.api.users.router import router as users_router
from identity.api.admin.router import router as admin_router
from identity.api.challenges.router import router as challenges_router

router = APIRouter()
router.include_router(auth_router, prefix="/auth", tags=["auth"])
router.include_router(users_router, prefix="/users", tags=["account"])
router.include_router(admin_router)
router.include_router(challenges_router, prefix="/challenges", tags=["challenges"])
