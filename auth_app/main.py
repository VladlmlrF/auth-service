import uvicorn
from fastapi import FastAPI


app = FastAPI(title="Authentication service")


if __name__ == "__main__":
    uvicorn.run("auth_app.main:app", reload=True)
