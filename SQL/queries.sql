--Users table creation--
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    firstname VARCHAR(255) NOT NULL,
    lastname VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    reset_token VARCHAR(255),
    reset_token_expiry TIMESTAMP,
    salt VARCHAR(255),
    login_attempts INTEGER NOT NULL DEFAULT 0,
	blocked BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_time TIMESTAMP 
);


--Usersunsecure table creation--
CREATE TABLE usersunsecure (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    firstname VARCHAR(255) NOT NULL,
    lastname VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    reset_token VARCHAR(255),
    reset_token_expiry TIMESTAMP,
    login_attempts INTEGER NOT NULL DEFAULT 0,
	blocked BOOLEAN NOT NULL DEFAULT FALSE,
    blocked_time TIMESTAMP 
);

--Clients table creation--
CREATE TABLE clients (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    client_id VARCHAR(255),
    email VARCHAR(255),
    phone VARCHAR(255)
);

--Password history table creation--
CREATE TABLE password_history (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

--Password history unsecure table creation--
CREATE TABLE password_history_unsecure (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
