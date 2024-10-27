import sys

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from auth_app.api.api_v1.auth.helpers import get_password_hash
from auth_app.core.config import settings
from auth_app.core.models import db_helper
from auth_app.core.models import Service
from auth_app.core.models import User
from auth_app.core.models import UserRole
from auth_app.logger import logger


def create_admin() -> None:
    """Creates an administrator with the role admin"""
    logger.info("Creating admin")

    session: Session = db_helper.get_session()

    try:
        existing_admin = session.execute(
            select(User).where(User.username == settings.ADMIN_USERNAME)
        ).scalar_one_or_none()

        if existing_admin:
            logger.warning("Admin already exists")
            return

        hashed_password = get_password_hash(settings.ADMIN_PASSWORD)

        admin = User(
            username=settings.ADMIN_USERNAME,
            email=settings.ADMIN_EMAIL,
            hashed_password=hashed_password,
        )
        session.add(admin)
        session.commit()
        session.refresh(admin)
        logger.info("Admin created successfully")

        service = session.execute(
            select(Service).where(Service.name == "auth")
        ).scalar_one_or_none()

        if not service:
            service = Service(name="auth")
            session.add(service)
            session.commit()
            session.refresh(service)
            logger.info("Service 'auth' created")

        existing_role = session.execute(
            select(UserRole).where(
                UserRole.user_id == admin.id,
                UserRole.service_id == service.id,
                UserRole.role == "admin",
            )
        ).scalar_one_or_none()

        if existing_role:
            logger.warning(
                f"Role 'admin' already assigned to user '{admin.username}' in service '{service.name}'"
            )
            return

        user_role = UserRole(user_id=admin.id, service_id=service.id, role="admin")
        session.add(user_role)
        session.commit()
        session.refresh(user_role)
        logger.info(
            f"Role 'admin' assigned to user '{admin.username}' in service '{service.name}'"
        )

    except SQLAlchemyError as error:
        session.rollback()
        logger.error(
            f"Failed to create admin due to database error: {error}", exc_info=True
        )
        sys.exit(1)
    finally:
        session.close()


if __name__ == "__main__":
    create_admin()
