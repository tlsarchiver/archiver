CREATE TABLE `certificates` (
    `id`                INTEGER NOT NULL UNIQUE,
	`host`	            TEXT NOT NULL,
    `ip`                TEXT,
	`ciphersuite`	    INT,
	`protocol`	        INT,
    `certificate_idx`   INT,
    `certificate_raw`   TEXT,
    `failed`            BOOLEAN DEFAULT false,
    `failure_error`     TEXT,
    `timestamp`         DATETIME NOT NULL,
	PRIMARY KEY(`id`)
);
