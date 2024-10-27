from pydantic import BaseModel


class TokenDataSchema(BaseModel):
    access_token: str
    token_type: str
