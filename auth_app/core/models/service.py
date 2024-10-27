from typing import TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from .base import Base

if TYPE_CHECKING:
    from .user_role import UserRole


class Service(Base):
    name: Mapped[str] = mapped_column(String(100), unique=True)
    roles: Mapped[list["UserRole"]] = relationship(
        back_populates="service", cascade="all, delete-orphan"
    )
