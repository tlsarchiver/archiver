package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
)

var (
	portNumber    int
	databaseURL   string
	conf          *tls.Config
	verbose       bool
	concurrency   int
	hostsFilename string
)

// CertStat groups the number of new certificates found and the name of the host
type CertStat struct {
	host     string
	newCerts int
}

// CommChans groups all the communication channels necessary to communicate
// between the workers
type CommChans struct {
	// The workers download and send the certs in this channel
	certsChan chan certProbe
	// To keep count of processed hosts
	countChan chan CertStat
}

func main() {
	log.SetFlags(log.Lshortfile)

	// Parse the command line parameters
	parseCommandLine()

	// Populates the db variable
	databaseURL = "certificates.sqlite3"
	SetupDB()

	// Configure the TLS client
	conf = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
	}

	// Load the hosts
	hosts := loadHostsList(hostsFilename)
	fmt.Printf("Loaded %d hosts from %s\n", len(hosts), hostsFilename)

	// Create the channel into which the grabber will send the certificates
	certsChan := make(chan certProbe)
	defer close(certsChan)

	// Create the channel to keep stats
	countChan := make(chan CertStat)
	defer close(countChan)

	// Loop on the list of hosts
	for workerID := 0; workerID < concurrency; workerID++ {
		// Cut the list
		workerHosts := hosts[len(hosts)/concurrency*workerID : len(hosts)/concurrency*(workerID+1)]
		if verbose {
			fmt.Printf("Starting worker #%d with %d hosts\n", workerID+1, len(workerHosts))
		}

		go runWorker(workerHosts, CommChans{certsChan, countChan})
	}

	// Display the stats in real-time
	go displayStats(countChan, len(hosts))

	// Receive the certProbes
	for true {
		cert := <-certsChan
		// TODO: check the return value of SaveCertificate
		SaveCertificate(cert)
	}
}

func runWorker(hosts []string, commChans CommChans) {
	for id := 0; id < len(hosts); id++ {
		// fmt.Printf("%f%% [%d/%d] %s\n", 100.*id/len(hosts), id, len(hosts), hosts[id])
		grabCert(hosts[id], commChans)
	}
}

func displayStats(countChan chan CertStat, hostsNumber int) {
	totalCertsProcessed := 0

	// For pretty-printing purposes only (number of digits for the hosts number)
	digitsHostsNumber := strconv.FormatFloat(math.Ceil(math.Log10(float64(hostsNumber))), 'f', -1, 64)

	for true {
		certStat := <-countChan
		totalCertsProcessed += certStat.newCerts

		fmt.Printf("%7.3f%% [%"+digitsHostsNumber+"d/%d] %s\n",
			100.*float32(totalCertsProcessed)/float32(hostsNumber),
			totalCertsProcessed,
			hostsNumber,
			certStat.host,
		)
	}
}
func loadHostsList(filename string) []string {

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
}
