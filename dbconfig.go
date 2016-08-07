package main

import (
	"fmt"
	"os"
	"strconv"
)

// The DatabaseConfig contains the configuration parameters for the database
type DatabaseConfig struct {
	dbType       string
	dbUser       string
	dbPassword   string
	dbHost       string
	dbPort       string
	maxOpenConns int
}

// Build the database URL from the parameters
func (dbc DatabaseConfig) buildDbURL() string {
	switch dbc.dbType {
	case "postgres":
		// TODO: better handling of the credentials (for instance, escape % characters)
		// Add ?sslmode=verify-full to the end if the server supports SSL
		return "postgres://" + dbc.dbUser + ":" + dbc.dbPassword + "@" + dbc.dbHost + ":" + dbc.dbPort + "/archives?sslmode=disable"
	}

	panic("Unhandled DB type " + dbc.dbType)
}

// Parse the configuration from the environment values
func parseConfiguration() DatabaseConfig {
	dbConfig := DatabaseConfig{}
	dbConfig.dbType = getEnv("ARCHIVER_DBTYPE", "postgres")
	dbConfig.dbUser = getEnv("ARCHIVER_DBUSER", "archiver")
	dbConfig.dbPassword = getEnv("ARCHIVER_DBPASSWORD", "")
	dbConfig.dbHost = getEnv("ARCHIVER_DBHOST", "localhost")
	dbConfig.dbPort = getEnv("ARCHIVER_DBPORT", "5432")

	var err error
	dbConfig.maxOpenConns, err = strconv.Atoi(getEnv("ARCHIVER_DBMAXOPENCONNS", "100"))
	checkErr(err)

	if configOptions.verbose {
		fmt.Printf("Database configuration: %+v\n", dbConfig)
	}

	return dbConfig
}

// Get the environment variable if present, or use a default value
func getEnv(envName string, defaultValue string) string {
	paramVal, varPresent := os.LookupEnv(envName)
	if !varPresent {
		return defaultValue
	}

	return paramVal
}
