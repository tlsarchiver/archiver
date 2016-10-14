package main

import (
	"database/sql"
	_ "github.com/lib/pq"
	"github.com/tlsarchiver/dbconnector"
)

var (
	db               *sql.DB
	stmtAddOk        *sql.Stmt
	stmtAddFail      *sql.Stmt
	stmtAddHost      *sql.Stmt
	stmtHostStarted  *sql.Stmt
	stmtHostFinished *sql.Stmt
)

// SetupDB initializes the DB
func SetupDB(dbConfig dbconnector.DatabaseConfig) {
	var err error

	db = dbconnector.SetupDB(dbConfig)

	// Prepare the requests we will be using
	stmtAddFail, err = db.Prepare("INSERT INTO certificates (host, ip, failed, failure_error, timestamp) VALUES ($1, $2, $3, $4, $5)")
	checkErr(err)

	stmtAddOk, err = db.Prepare("INSERT INTO certificates (host, ip, protocol, ciphersuite, certificate_idx, certificate_raw, timestamp, cert_content, cert_sha1) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
	checkErr(err)

	stmtAddHost, err = db.Prepare(
		`INSERT INTO hosts (host)
        SELECT CAST($1 AS VARCHAR)
        WHERE NOT EXISTS
        (SELECT id FROM hosts WHERE host = $1);`,
	)
	checkErr(err)

	stmtHostStarted, err = db.Prepare("UPDATE hosts SET started_on = now() WHERE host = $1")
	checkErr(err)

	stmtHostFinished, err = db.Prepare("UPDATE hosts SET finished = true WHERE host = $1")
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
		res, err = stmtAddFail.Exec(cert.host, cert.IP, true, cert.failure.Error(), cert.timestamp)
	} else {
		// Save the certificate & connection data
		res, err = stmtAddOk.Exec(
			cert.host,
			cert.IP,
			cert.protocol,
			cert.cipherSuite,
			cert.certID,
			cert.cert.Raw,
			cert.timestamp,
			cert.certData,
			cert.certSHA1,
		)
	}
	checkErr(err)
	affect, err := res.RowsAffected()
	checkErr(err)

	return affect
}

// loadHostsListFromDB returns a list of hosts to process from the DB
func loadHostsListFromDB() []string {
	// Extract hosts from DB (not finished and started more than 1h ago)
	rows, err := db.Query("SELECT host FROM hosts WHERE NOT finished AND (started_on IS NULL OR now() - started_on > interval '1 hour')")
	checkErr(err)

	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var host string
		err = rows.Scan(&host)
		checkErr(err)
		hosts = append(hosts, host)
	}

	return hosts
}

// Saves the list of hosts into the DB
func saveHostsListsToDB(hosts []string) int64 {
	var affected int64
	affected = 0
	for hostI := 0; hostI < len(hosts); hostI++ {
		res, err := stmtAddHost.Exec(hosts[hostI])
		checkErr(err)
		affect, err := res.RowsAffected()
		checkErr(err)
		affected += affect
	}

	return affected
}

func markHostStared(host string) {
	_, err := stmtHostStarted.Exec(host)
	checkErr(err)
}

func markHostFinished(host string) {
	_, err := stmtHostFinished.Exec(host)
	checkErr(err)
}
