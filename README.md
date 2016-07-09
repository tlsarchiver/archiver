# TLS Archive

This archiver expects to find a PostgreSQL database, with all the schemas in place.

## TODO

* [check] Log failures
* [check] Log timestamp
* [check] Display progress
* use a proper system for configuration values

* [begun] Write a small UI (Go ?) to display the results, per host
* Display the results per Public Key fingerprint

## Known bugs

* on the first run, the DB is created but something goes wrong and the program has to be re-started (?) [nope ?]

## Dockerizing it

First, build the static executable, then build the container:

    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o archiver .
    sudo docker build -t tls-archiver .
