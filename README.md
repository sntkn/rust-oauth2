# rust-oauth2

## Cargo

### Hot Reload

```bash
cargo watch -x run

# with database configuration
DATABASE_URL=postgres://app:pass@localhost/auth cargo watch -x run
```

## OAuth2

- Axum
- SeaORM

### Endpoint

- GET /authorize -> display authorization information
- POST /authorization -> return authorization code
- POST /token -> return token information
- GET /me -> return user information
- DELETE /token -> revoke token

#### API

- GET /articles
- GET /articles/{article_id}
- POST /articles
- PUT  /articles/{article_id}
- POST /articles/{article_id}/publish
- PUT  /articles/{article_id}
- DELETE /articles/{article_id}

## PostgreSQL

```zsh
# login
docker compose exec database psql -U app auth

# create entity
sea-orm-cli generate entity -u postgres://admin:admin@localhost/auth -o src/entity
```

## 教訓

- State は引数の最初に書くこと。後ろに書くと型エラーが起こる（Form で）
