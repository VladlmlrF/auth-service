from fastapi import APIRouter
from fastapi import Depends
from fastapi import Query
from sqlalchemy.orm import Session

from auth_app.api.api_v1.auth.helpers import RoleChecker
from auth_app.api.api_v1.users import crud
from auth_app.api.api_v1.users.schemas import RoleCreateSchema
from auth_app.api.api_v1.users.schemas import RoleSchema
from auth_app.api.api_v1.users.schemas import UserCreateSchema
from auth_app.api.api_v1.users.schemas import UserSchema
from auth_app.core.models import db_helper

router = APIRouter(tags=["Users"])
admin_required = RoleChecker("auth", ["admin"])


@router.get("/", response_model=list[UserSchema])
def read_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1),
    session: Session = Depends(db_helper.get_db),
    _: None = Depends(admin_required),
):
    users = crud.get_users(session=session, skip=skip, limit=limit)
    return users


@router.post("/", response_model=UserSchema)
def create_user(
    user: UserCreateSchema,
    session: Session = Depends(db_helper.get_db),
    _: None = Depends(admin_required),
):
    new_user = crud.create_user(session=session, user=user)
    return new_user


@router.post("/{username}/roles", response_model=RoleSchema)
def add_role_to_user(
    username: str,
    role_data: RoleCreateSchema,
    session: Session = Depends(db_helper.get_db),
    _: None = Depends(admin_required),
):
    user_role = crud.add_user_role(
        session=session, username=username, role_data=role_data
    )
    return user_role


@router.delete("/{username}")
def delete_user(
    username: str,
    session: Session = Depends(db_helper.get_db),
    _: None = Depends(admin_required),
):
    crud.delete_user(session=session, username=username)
    return {"detail": f"User '{username}' deleted successfully"}
