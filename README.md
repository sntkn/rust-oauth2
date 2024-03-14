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
