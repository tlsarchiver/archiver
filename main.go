package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	portNumber    int
	databaseURL   string
	databaseType  string
	conf          *tls.Config
	verbose       bool
	concurrency   int
	hostsFilename string
	finishedFlag  bool
	hostsFromDB   bool
	hostsToDB     bool
)

// CommChans groups all the communication channels necessary to communicate
// between the workers
type CommChans struct {
	// The workers download and send the certs in this channel
	certsChan chan certProbe
	// To keep count of processed certs
	countChan chan CertStat
	// To keep count of processed hosts
	hostCountChan chan int
	// State of the workers, to detect when all hosts have been parsed
	workersStateChan chan int
}

func main() {
	log.SetFlags(log.Lshortfile)

	// Parse the command line parameters
	parseCommandLine()

	// Populates the db variable
	// databaseURL = "certificates.sqlite3"
	dbUser := "archiver"
	dbPassword := ":Sd_NTy]Nn[`<^,+1}3itM^N3#nw"
	dbPassword = "kikoo"
	dbHost := "localhost"
	dbPort := "5432"

	databaseType = "postgres"
	// TODO: better handling of the credentials (for instance, escape % characters)
	// Add ?sslmode=verify-full to the end if the server supports SSL
	databaseURL = "postgres://" + dbUser + ":" + dbPassword + "@" + dbHost + ":" + dbPort + "/archives?sslmode=disable"
	SetupDB()

	// Configure the TLS client
	conf = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
	}

	// Load the hosts
	var hosts []string
	if hostsFromDB {
		hosts = loadHostsListFromDB()
		fmt.Printf("Loaded %d hosts from database\n", len(hosts))
	} else {
		hosts = loadHostsListFromFile(hostsFilename)
		fmt.Printf("Loaded %d hosts from %s\n", len(hosts), hostsFilename)

		if hostsToDB {
			affected := saveHostsListsToDB(hosts)
			fmt.Printf("Saved %d new hosts to the database\n", affected)
		}
	}

	finishedFlag = false

	// Create the channel into which the grabber will send the certificates
	certsChan := make(chan certProbe)
	defer close(certsChan)

	// Create the channels to keep stats
	countChan := make(chan CertStat)
	hostCountChan := make(chan int)
	defer close(countChan)
	defer close(hostCountChan)

	// Create the channel for worker statuses
	workersStateChan := make(chan int)
	defer close(workersStateChan)

	// Package all these channels
	commChans := CommChans{certsChan, countChan, hostCountChan, workersStateChan}

	// Loop on the list of hosts
	for workerID := 0; workerID < concurrency; workerID++ {
		// Cut the list
		workerHosts := hosts[len(hosts)/concurrency*workerID : len(hosts)/concurrency*(workerID+1)]
		if verbose {
			fmt.Printf("Starting worker #%d with %d hosts\n", workerID+1, len(workerHosts))
		}

		go runWorker(workerHosts, commChans)
	}

	// Display the stats in real-time
	go displayStats(commChans, len(hosts))

	// Detect end of execution for the workers
	go monitorWorkers(commChans, concurrency)

	// Receive the certProbes
	for !finishedFlag {
		cert := <-certsChan
		// TODO: check the return value of SaveCertificate
		SaveCertificate(cert)
	}

	// Don't forget to close the DB
	CloseDB()
}

func runWorker(hosts []string, commChans CommChans) {
	for id := 0; id < len(hosts); id++ {
		// One new host processed
		commChans.hostCountChan <- 1
		markHostStared(hosts[id])
		grabCert(hosts[id], commChans)
		markHostFinished(hosts[id])
	}
	// When all the hosts have been processed, signal it
	commChans.workersStateChan <- 1
}

func loadHostsListFromFile(filename string) []string {

	// Open the given file, one host per line
	f, err := os.Open(filename)
	checkErr(err)

	// Don't forget to close the file
	defer f.Close()

	var hosts []string

	// Parse the file, line by line, with a scanner
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		hosts = append(hosts, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	return hosts
}

func monitorWorkers(commChans CommChans, workers int) {
	workersLeft := workers

	for workersLeft > 0 {
		finishedWorker := <-commChans.workersStateChan
		workersLeft -= finishedWorker
	}

	fmt.Printf("All %d workers have terminated, sending stop signal...\n", workers)
	finishedFlag = true
}

func checkErr(err error) {
	if err != nil {
		log.Println(err)
		panic("Aborting.")
	}
}

func parseCommandLine() {
	flag.IntVar(&concurrency, "concurrency", 50,
		"Number of workers")
	flag.BoolVar(&verbose, "v", false, "Verbose logging")
	flag.BoolVar(&hostsToDB, "hoststodb", false, "Load hosts to the DB")
	flag.BoolVar(&hostsFromDB, "hostsfromdb", false, "Load hosts from the DB")
	flag.StringVar(&hostsFilename, "f", "top-hosts-alexa.txt",
		"File containing the list of hosts to scan")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, strings.Join([]string{
			"Retrieve the TLS certificate of the given hosts and stores the results inside a database.",
			"",
			"Usage: ./tls-cert-shopping [-f top-hosts-alexa.txt] [-v] [-concurrency 50]",
			"",
		}, "\n"))
		flag.PrintDefaults()
	}

	flag.Parse()

	if hostsFromDB && hostsToDB {
		fmt.Fprintln(os.Stderr, "You cannot load the hosts from the DB and write them to the DB, no host will be written in the DB!")
	}
}
