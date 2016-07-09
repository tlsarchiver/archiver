package main

import (
	"database/sql"
	_ "github.com/lib/pq"
)

var (
	db          *sql.DB
	stmtAddOk   *sql.Stmt
	stmtAddFail *sql.Stmt
)

// SetupDB initializes the DB (create the file if necessary)
func SetupDB() {
	var err error

	// Open the database, being sure it has been installed
	db, _ = sql.Open(databaseType, databaseURL)

	// Prepare the requests we will be using
	stmtAddFail, err = db.Prepare("INSERT INTO certificates (host, ip, failed, failure_error, timestamp) VALUES ($1, $2, $3, $4, $5)")
	checkErr(err)

	stmtAddOk, err = db.Prepare("INSERT INTO certificates (host, ip, protocol, ciphersuite, certificate_idx, certificate_raw, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7)")
	checkErr(err)
}

// CloseDB closes the DB
func CloseDB() {
	db.Close()
}

// SaveCertificate adds the certificate in the DB
func SaveCertificate(cert certProbe) int64 {
	var err error
	var res sql.Result
	if cert.failure != nil {
		// Just save the failure
		res, err = stmtAddFail.Exec(cert.host, cert.IP, true, string(cert.failure.Error()), cert.timestamp)
	} else {
		// Save the certificate & connection data
		res, err = stmtAddOk.Exec(cert.host, cert.IP, cert.protocol, cert.cipherSuite, cert.certID, cert.cert.Raw, cert.timestamp)
	}
	checkErr(err)
	affect, err := res.RowsAffected()
	checkErr(err)

	return affect
}
