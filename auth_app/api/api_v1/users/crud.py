from fastapi import HTTPException
from fastapi import status
from sqlalchemy import select
from sqlalchemy.engine import Result
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from auth_app.api.api_v1.auth.helpers import get_password_hash
from auth_app.api.api_v1.auth.helpers import get_user_by_username
from auth_app.api.api_v1.users.schemas import RoleCreateSchema
from auth_app.api.api_v1.users.schemas import UserCreateSchema
from auth_app.core.models import Service
from auth_app.core.models import User
from auth_app.core.models import UserRole
from auth_app.logger import logger


def create_user(session: Session, user: UserCreateSchema) -> User:
    """Create new user"""
    logger.info(f"Creating new user: {user.username}")
    try:
        existing_user = session.execute(
            select(User).where(
                (User.username == user.username) | (User.email == user.email)
            )
        ).scalar_one_or_none()
        if existing_user:
            logger.warning(
                f"User with username '{user.username}' or email '{user.email}' already exists"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already registered",
            )

        hashed_password = get_password_hash(user.password)

        new_user = User(
            username=user.username, email=user.email, hashed_password=hashed_password
        )
        session.add(new_user)
        session.commit()
        session.refresh(new_user)
        logger.info(f"User created successfully: {new_user.id}")
        return new_user
    except SQLAlchemyError as error:
        session.rollback()
        logger.error(
            f"Failed to create user due to database error: {error}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user",
        )


def get_users(session: Session, skip: int = 0, limit: int = 20) -> list[User]:
    """Get list of users with pagination"""
    logger.info(f"Retrieving users with skip={skip} and limit={limit}")
    try:
        statement = select(User).offset(skip).limit(limit).order_by(User.id)
        result: Result = session.execute(statement=statement)
        users = result.scalars().all()
        logger.info("Users successfully received")
        return list(users)
    except SQLAlchemyError as error:
        logger.error(
            f"Failed to retrieve users due to database error: {error}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get users",
        )


def delete_user(session: Session, username: str) -> None:
    """Delete user"""
    logger.info(f"Deleting user: {username}")
    try:
        user = get_user_by_username(session=session, username=username)
        if user:
            session.delete(user)
            session.commit()
            logger.info(f"User {username} successfully deleted")
        else:
            logger.warning(f"User '{username}' not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
    except SQLAlchemyError as error:
        session.rollback()
        logger.error(
            f"Failed to delete user {username} due to database error: {error}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user",
        )


def add_user_role(
    session: Session,
    username: str,
    role_data: RoleCreateSchema,
) -> UserRole:
    """Add role to user for specific service"""
    logger.info(
        f"Adding role {role_data.role} for user {username} in service {role_data.service.name}"
    )
    try:
        user = get_user_by_username(session=session, username=username)
        if not user:
            logger.warning(f"User '{username}' not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        service = session.execute(
            select(Service).where(Service.name == role_data.service.name)
        ).scalar_one_or_none()
        if not service:
            service = Service(name=role_data.service.name)
            session.add(service)
            session.commit()
            session.refresh(service)
            logger.info(f"Service '{role_data.service}' created")

        existing_role = session.execute(
            select(UserRole).where(
                UserRole.user_id == user.id, UserRole.service_id == service.id
            )
        ).scalar_one_or_none()
        if existing_role:
            logger.warning(
                f"User '{username}' already has a role in service '{role_data.service}'"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already has a role in this service",
            )

        user_role = UserRole(
            user_id=user.id, service_id=service.id, role=role_data.role.value
        )
        session.add(user_role)
        session.commit()
        session.refresh(user_role)
        logger.info(
            f"Role {role_data.role} added to user {username} for service {role_data.service}"
        )
        return user_role
    except SQLAlchemyError as error:
        session.rollback()
        logger.error(
            f"Failed to add role due to database error: {error}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add role to user",
        )
