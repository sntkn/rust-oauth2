CREATE USER app WITH PASSWORD 'pass';
CREATE DATABASE auth;

--ユーザーにDBの権限をまとめて付与
GRANT ALL PRIVILEGES ON DATABASE auth TO app;

-- auth データベースに接続
\c auth;

-- users テーブル
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT current_timestamp,
    updated_at TIMESTAMP DEFAULT current_timestamp
);

-- oauth2_clients テーブル
CREATE TABLE oauth2_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    redirect_uris VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT current_timestamp,
    updated_at TIMESTAMP DEFAULT current_timestamp
);

-- oauth2_codes テーブル
CREATE TABLE oauth2_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id UUID NOT NULL,
    user_id UUID NOT NULL,
    scope VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP DEFAULT NULL,
    created_at TIMESTAMP DEFAULT current_timestamp,
    updated_at TIMESTAMP DEFAULT current_timestamp,
    FOREIGN KEY (client_id) REFERENCES oauth2_clients (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- oauth2_tokens テーブル
CREATE TABLE oauth2_tokens (
    access_token VARCHAR(512) PRIMARY KEY,
    client_id UUID NOT NULL,
    user_id UUID NOT NULL,
    scope VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP DEFAULT NULL,
    created_at TIMESTAMP DEFAULT current_timestamp,
    updated_at TIMESTAMP DEFAULT current_timestamp,
    FOREIGN KEY (client_id) REFERENCES oauth2_clients (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- oauth2_refresh_tokens テーブル
CREATE TABLE oauth2_refresh_tokens (
    refresh_token VARCHAR(255) PRIMARY KEY,
    access_token VARCHAR(512) NOT NULL,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT current_timestamp,
    updated_at TIMESTAMP DEFAULT current_timestamp,
    FOREIGN KEY (access_token) REFERENCES oauth2_tokens (access_token)
);

--ユーザーにテーブル操作権限をまとめて付与
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app;
