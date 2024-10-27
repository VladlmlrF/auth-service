from datetime import datetime
from datetime import timedelta
from typing import Annotated

from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi import status
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from jose import ExpiredSignatureError
from jose import jwt
from jose import JWTError
from jose.exceptions import JWTClaimsError
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from auth_app.core.config import auth_settings
from auth_app.core.models import db_helper
from auth_app.core.models import User
from auth_app.logger import logger

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

PRIVATE_KEY = auth_settings.private_key_path.read_text()
PUBLIC_KEY = auth_settings.public_key_path.read_text()
ALGORITHM = auth_settings.algorithm


class OAuth2PasswordBearerWithCookie(OAuth2):
    def __init__(
        self,
        tokenUrl: str,
        scheme_name: str | None = None,
        scopes: dict[str, str] | None = None,
        auto_error: bool = True,
    ) -> None:
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> str | None:
        authorization: str = request.cookies.get("access_token")

        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            token = request.cookies.get("access_token")
            if not token:
                if self.auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                else:
                    return None
            return token
        else:
            return param


oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="/api/v1/auth/login")


def get_password_hash(password: str) -> str:
    """Hash the password"""
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Password verification"""
    return pwd_context.verify(password, hashed_password)


def create_access_token(
    payload: dict,
    algorithm: str = ALGORITHM,
    private_key: str = PRIVATE_KEY,
    expires_timedelta: timedelta | None = None,
    expire_minutes: int = auth_settings.access_token_expire_minutes,
) -> str:
    """Encode token"""
    to_encode = payload.copy()
    now = datetime.utcnow()
    if expires_timedelta:
        expire = now + expires_timedelta
    else:
        expire = now + timedelta(minutes=expire_minutes)
    to_encode.update({"exp": expire})
    try:
        encoded_jwt = jwt.encode(claims=to_encode, key=private_key, algorithm=algorithm)
        logger.info(f"Access token created for user: {payload.get('sub')}")
        return encoded_jwt
    except JWTError as error:
        logger.error(
            f"Error encoding JWT for user {payload.get('sub')}: {error}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create token",
        )


def decode_access_token(
    token: str,
    public_key: str = PUBLIC_KEY,
    algorithm: str = ALGORITHM,
) -> dict:
    """Decode token"""
    try:
        decoded = jwt.decode(token=token, key=public_key, algorithms=[algorithm])
        logger.info(f"Access token decoded successfully: {decoded.get('sub')}")
        return decoded
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTClaimsError:
        logger.warning("Invalid claims in access token.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid claims",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as error:
        logger.error(f"Error decoding JWT: {error}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_user_by_username(session: Session, username: str) -> User | None:
    """Get user by username"""
    logger.info(f"Retrieving user: {username}")
    try:
        statement = select(User).where(User.username == username)
        user = session.scalar(statement=statement)
        if not user:
            logger.info(f"User {username} not found")
            return None
        logger.info(f"User {username} successfully received.")
        return user
    except SQLAlchemyError as error:
        logger.error(
            f"Failed to retrieve user {username} due to database error: {error}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user by username",
        )


def get_user_by_email(session: Session, email: str) -> User | None:
    """Get user by email"""
    logger.info(f"Retrieving user with email {email}")
    try:
        statement = select(User).where(User.email == email)
        user = session.scalar(statement=statement)
        if not user:
            logger.info(f"User with email {email} not found")
            return None
        logger.info(f"User with email {email} successfully received.")
        return user
    except SQLAlchemyError as error:
        logger.error(
            f"Failed to retrieve user with email {email} due to database error: {error}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user by email",
        )


def authenticate_user(session: Session, identifier: str, password: str) -> User | None:
    """Checking user authentication by username or by email"""
    logger.info(f"Attempting to authenticate user: {identifier}")
    user = get_user_by_username(session=session, username=identifier)
    if not user:
        user = get_user_by_email(session=session, email=identifier)
    if not user or not verify_password(
        password=password, hashed_password=user.hashed_password
    ):
        logger.warning(f"Authentication failed for user {identifier}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logger.info(f"User {identifier} authenticated successfully")
    return user


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Session = Depends(db_helper.get_db),
) -> User:
    """Get current user by JWT token"""
    logger.info("Attempting to validate and decode access token.")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload: dict = decode_access_token(token=token)
    username: str | None = payload.get("sub")
    if username is None:
        logger.warning(
            "Token validation failed: username (sub) is missing in token payload."
        )
        raise credentials_exception

    user = get_user_by_username(session, username)

    if not user:
        logger.warning(
            f"User retrieval failed: User with username {username} not found."
        )
        raise credentials_exception
    logger.info(f"User {username} successfully retrieved and validated.")
    return user
