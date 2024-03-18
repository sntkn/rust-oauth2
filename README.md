# rust-oauth2

## OAuth2

- Axum
- SeaORM

## PostgreSQL

```zsh
# login
docker compose exec database psql -U app auth

# create entity
sea-orm-cli generate entity -u postgres://admin:admin@localhost/auth -o src/entity
```

## Endpoint

- GET /authorize -> display authorization information
- POST /authorization -> return authorization code
- POST /token -> return token information
- GET /me -> return user information
- DELETE /token -> revoke token
