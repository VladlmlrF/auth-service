# auth-service
## Установка проекта:

Клонировать проект из Github командой:
```commandline
git clone https://github.com/VladlmlrF/auth-service.git
```

## Запуск проекта:

1. Создать файл `.env` в котором должны быть следующие записи:
```dotenv
DB_HOST=db
DB_PORT=5432
DB_NAME=postgres
DB_USER=postgres
DB_PASS=postgres
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
DATABASE_URL=postgresql://postgres:postgres@db:5432/postgres
ADMIN_PASSWORD=123456
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@gmail.com
```

2. Непосредственно запустить проект в контейнере командой:
```commandline
docker compose up --build
```
