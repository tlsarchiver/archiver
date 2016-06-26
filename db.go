package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io/ioutil"
	"os"
)

var (
	db *sql.DB
)

// SetupDB initializes the DB (create the file if necessary)
func SetupDB() {
	if _, err := os.Stat(databaseURL); os.IsNotExist(err) {
		// The database does not exist, attempt to create it
		fmt.Print("Database not found, trying to initialize it...")
		db, err = sql.Open("sqlite3", databaseURL)
		checkErr(err)

		body, err := ioutil.ReadFile("initdb.sql")
		checkErr(err)

		_, err = db.Exec(string(body))
		checkErr(err)

		db.Close()
		fmt.Print(" done.\n")
	}

	db, _ = sql.Open("sqlite3", databaseURL)
}

// SaveCertificate adds the certificate in the DB
func SaveCertificate(cert certProbe) int64 {
	var err error
	var res sql.Result
	if cert.failure != nil {
		// Just save the failure
		stmt, _ := db.Prepare("INSERT INTO certificates (host, ip, failed, failure_error, timestamp) VALUES (?, ?, ?, ?, ?)")
		res, err = stmt.Exec(cert.host, cert.IP, true, string(cert.failure.Error()), cert.timestamp)
	} else {
		// Save the certificate & connection data
		stmt, _ := db.Prepare("INSERT INTO certificates (host, ip, protocol, ciphersuite, certificate_idx, certificate_raw, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)")
		res, err = stmt.Exec(cert.host, cert.IP, cert.protocol, cert.cipherSuite, cert.certID, cert.cert.Raw, cert.timestamp)
	}
	checkErr(err)
	affect, err := res.RowsAffected()
	checkErr(err)

	return affect
}
