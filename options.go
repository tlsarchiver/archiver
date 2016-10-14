package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// ConfigOptions holds the various runtime options
type ConfigOptions struct {
	// How many workers should we spawn?
	concurrency int
	// What is the filename of the list of hosts to load?
	hostsFilename string
	// Should we load the hosts from the database?
	hostsFromDB bool
	// ...or write the hosts list to the database?
	hostsToDB bool
	// Should we only use IPV4 addresses?
	IPv4only bool
	// ...or IPv6 only?
	IPv6only bool
	// Should we provide verbose output?
	verbose bool
}

func parseCommandLine() {
	flag.IntVar(&configOptions.concurrency, "concurrency", 50,
		"Number of workers")
	flag.BoolVar(&configOptions.verbose, "v", false, "Verbose logging")
	flag.BoolVar(&configOptions.IPv4only, "4", false, "Only scan IPv4 hosts")
	flag.BoolVar(&configOptions.IPv6only, "6", false, "Only scan IPv6 hosts")
	flag.BoolVar(&configOptions.hostsToDB, "hoststodb", false, "Load hosts to the DB")
	flag.BoolVar(&configOptions.hostsFromDB, "hostsfromdb", false, "Load hosts from the DB")
	flag.StringVar(&configOptions.hostsFilename, "f", "top-hosts-alexa.txt",
		"File containing the list of hosts to scan")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, strings.Join([]string{
			"Retrieve the TLS certificate of the given hosts and stores the results inside a database.",
			"",
			"Usage: " + os.Args[0] + " [-f top-hosts-alexa.txt] [-v] [-concurrency 50]",
			"",
		}, "\n"))
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, strings.Join([]string{
			"",
			"Database configuration is set through environment variables:",
			"* ARCHIVER_DBUSER \t(default: archiver)",
			"* ARCHIVER_DBPASSWORD \t(default: empty)",
			"* ARCHIVER_DBHOST \t(default: localhost)",
			"* ARCHIVER_DBPORT \t(default: 5432)",
			"* ARCHIVER_DBTYPE \t(default: postgres)",
			"* ARCHIVER_DBMAXOPENCONNS \t(default: 100)",
			"",
		}, "\n"))
	}

	flag.Parse()

	if !configOptions.checkConfiguration() {
		os.Exit(1)
	}
}

func (conf ConfigOptions) checkConfiguration() bool {

	if conf.hostsFromDB && conf.hostsToDB {
		fmt.Fprintln(os.Stderr, "You cannot load the hosts from the DB and write them to the DB, no host will be written in the DB!")
		return false
	}

	if conf.IPv4only && conf.IPv6only {
		fmt.Fprintln(os.Stderr, "You cannot scan hosts using only IPv4 AND only IPv6, that doesn't make any sense, dude...")
		return false
	}
	return true
}
