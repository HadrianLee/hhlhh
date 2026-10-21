from fastapi import APIRouter, Depends

from bff.api.apps.router import router as apps_router
from bff.api.auth.router import router as auth_router
from bff.api.dependencies import csrf_protection
from bff.api.identity.router import router as identity_router
from bff.exception_handlers import PROBLEM_RESPONSES

router = APIRouter(dependencies=[Depends(csrf_protection)], responses=PROBLEM_RESPONSES)
router.include_router(auth_router, prefix="/auth", tags=["browser sessions"])
router.include_router(identity_router, tags=["identity gateway"])
router.include_router(apps_router, prefix="/apps", tags=["application gateway"])
