import uvicorn
from fastapi import FastAPI

from auth_app.api import router as api_router


app = FastAPI(title="Authentication service")

app.include_router(api_router)


if __name__ == "__main__":
    uvicorn.run("auth_app.main:app", reload=True)
