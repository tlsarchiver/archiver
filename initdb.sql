CREATE TABLE certificates (
    id                SERIAL PRIMARY KEY,
    host              TEXT NOT NULL,
    ip                TEXT,
    ciphersuite       INT,
    protocol          INT,
    certificate_idx   INT,
    cert_sha1         CHAR(40),
    certificate_raw   BYTEA,
    failed            BOOLEAN DEFAULT false,
    failure_error     TEXT,
    timestamp         TIMESTAMP WITH TIME ZONE NOT NULL,
    cert_content      JSONB
);

CREATE INDEX on certificates (cert_sha1);

CREATE TABLE hosts (
    id                SERIAL PRIMARY KEY,
    host              VARCHAR(255) NOT NULL UNIQUE,
    started_on        TIMESTAMP WITH TIME ZONE,
    finished          BOOLEAN DEFAULT false
);
