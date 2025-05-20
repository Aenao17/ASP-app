CREATE TABLE users (
                       id SERIAL PRIMARY KEY,
                       username VARCHAR(255) UNIQUE NOT NULL,
                       password TEXT NOT NULL,
                       email VARCHAR(255) UNIQUE NOT NULL,
                       institutional_email VARCHAR(255),
                       first_name VARCHAR(255),
                       last_name VARCHAR(255),
                       phone_number VARCHAR(50),
                       role VARCHAR(50)
);

CREATE TABLE token (
                       id SERIAL PRIMARY KEY,
                       token_type VARCHAR(50),
                       revoked BOOLEAN,
                       expired BOOLEAN,
                       user_id BIGINT REFERENCES users(id)
);