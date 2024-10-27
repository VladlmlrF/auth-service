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

2. Создать приватный и публичный ключи. Для этого:
- создать папку `certs` в корне проекта
- перейти в эту папку и выполнить в терминале две команды:
```commandline
openssl genrsa -out private.pem 2048
```
```commandline
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

3. Непосредственно запустить проект в контейнере командой:
```commandline
docker compose up --build
```
