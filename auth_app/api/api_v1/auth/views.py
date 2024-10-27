from fastapi import APIRouter
from fastapi import Depends
from fastapi import Form
from fastapi import HTTPException
from fastapi import Response
from fastapi import status
from sqlalchemy.orm import Session

from .helpers import authenticate_user
from .helpers import create_access_token
from .schemas import TokenDataSchema
from auth_app.core.config import auth_settings
from auth_app.core.models import db_helper

router = APIRouter(tags=["Auth"])


@router.post("/login", response_model=TokenDataSchema)
def login_for_access_token(
    response: Response,
    username: str = Form(
        title="username or email", description="Enter your username or email address"
    ),
    password: str = Form(),
    session: Session = Depends(db_helper.get_db),
):
    user = authenticate_user(session=session, identifier=username, password=password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = {"sub": user.username, "username": user.username, "email": user.email}
    token = create_access_token(payload=payload)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=auth_settings.access_token_expire_minutes * 60,
        expires=auth_settings.access_token_expire_minutes * 60,
    )
    return TokenDataSchema(access_token=token, token_type="Bearer")
