CREATE TABLE certificates (
    id                SERIAL PRIMARY KEY,
    host              TEXT NOT NULL,
    ip                TEXT,
    ciphersuite       INT,
    protocol          INT,
    certificate_idx   INT,
    certificate_raw   BYTEA,
    failed            BOOLEAN DEFAULT false,
    failure_error     TEXT,
    timestamp         TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE hosts (
    id                SERIAL PRIMARY KEY,
    host              VARCHAR(255) NOT NULL UNIQUE,
    started_on        TIMESTAMP WITH TIME ZONE,
    finished          BOOLEAN DEFAULT false
);
