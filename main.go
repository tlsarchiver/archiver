package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/tlsarchiver/dbconnector"
	"log"
	"os"
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

var (
	conf          *tls.Config
	finishedFlag  bool
	configOptions ConfigOptions
)

func main() {
	log.SetFlags(log.Lshortfile)

	// Parse the command line parameters
	parseCommandLine()

	// Populates the db configuration from the environment variables
	dbConfig := dbconnector.ParseConfiguration()

	// Setup the DB
	SetupDB(dbConfig)

	// Configure the TLS client
	conf = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
	}

	// Load the hosts
	var hosts []string
	if configOptions.hostsFromDB {
		hosts = loadHostsListFromDB()
		fmt.Printf("Loaded %d hosts from database\n", len(hosts))
	} else {
		hosts = loadHostsListFromFile(configOptions.hostsFilename)
		fmt.Printf("Loaded %d hosts from %s\n", len(hosts), configOptions.hostsFilename)

		if configOptions.hostsToDB {
			fmt.Println("Saving these hosts into the database...")
			affected := saveHostsListsToDB(hosts)
			fmt.Printf("Saved %d new hosts to the database. Exiting...\n", affected)
			fmt.Println("You can now re-run the archiver with the -hostsfromdb flag to use the loaded hosts(s).")
			os.Exit(0)
		}
	}

	if len(hosts) > 0 {

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
		for workerID := 0; workerID < configOptions.concurrency; workerID++ {
			// Cut the list
			workerHosts := hosts[len(hosts)/configOptions.concurrency*workerID : len(hosts)/configOptions.concurrency*(workerID+1)]
			if configOptions.verbose {
				fmt.Printf("Starting worker #%d with %d hosts\n", workerID+1, len(workerHosts))
			}

			go runWorker(workerHosts, commChans)
		}

		// Display the stats in real-time
		go displayStats(commChans, len(hosts))

		// Detect end of execution for the workers
		go monitorWorkers(commChans, configOptions.concurrency)

		// Receive the certProbes
		for !finishedFlag {
			cert := <-certsChan
			// TODO: check the return value of SaveCertificate
			SaveCertificate(cert)
		}
	}

	// Don't forget to close the DB
	CloseDB()
}

func runWorker(hosts []string, commChans CommChans) {
	for id := 0; id < len(hosts); id++ {
		// One new host processed
		commChans.hostCountChan <- 1

		if configOptions.hostsFromDB {
			markHostStared(hosts[id])
		}

		// Actually do the job
		grabCert(hosts[id], commChans)

		if configOptions.hostsFromDB {
			markHostFinished(hosts[id])
		}
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
