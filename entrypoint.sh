#!/bin/sh

uvicorn auth_app.main:app --host 0.0.0.0 --port 8001
