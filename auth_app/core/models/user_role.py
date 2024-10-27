from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from .base import Base

if TYPE_CHECKING:
    from .user import User
    from .service import Service


class UserRole(Base):
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"))
    role: Mapped[str]
    user: Mapped["User"] = relationship(back_populates="roles")
    service: Mapped["Service"] = relationship(back_populates="roles")

    __table_args__ = (
        UniqueConstraint("user_id", "service_id", name="_user_service_uc"),
    )
