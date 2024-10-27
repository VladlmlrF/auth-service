from enum import Enum

from pydantic import BaseModel
from pydantic import EmailStr
from pydantic import field_validator


class RoleEnum(str, Enum):
    admin = "admin"
    client = "client"


class ServiceSchema(BaseModel):
    name: str


class RoleBaseSchema(BaseModel):
    service: ServiceSchema
    role: RoleEnum


class RoleCreateSchema(RoleBaseSchema):
    pass


class RoleSchema(RoleBaseSchema):
    id: int


class UserBaseSchema(BaseModel):
    username: str
    email: EmailStr

    @field_validator("username")
    def validate_username(cls, value):
        if len(value) < 4:
            raise ValueError("Username must be at least 4 characters long")
        return value


class UserCreateSchema(UserBaseSchema):
    password: str

    @field_validator("password")
    def validate_username(cls, value):
        if len(value) < 6:
            raise ValueError("Password must be at least 6 characters long")
        return value


class UserSchema(UserBaseSchema):
    id: int
    roles: list[RoleSchema] = []
