package main

import (
	"fmt"
	"math"
	"strconv"
)

// CertStat groups the number of new certificates found and the name of the host
type CertStat struct {
	host     string
	newCerts int
}

func displayStats(commChans CommChans, hostsNumber int) {
	totalCertsProcessed := 0

	// For pretty-printing purposes only (number of digits for the hosts number)
	digitsHostsNumber := strconv.FormatFloat(math.Ceil(math.Pow(float64(hostsNumber), 1./10.)), 'f', -1, 64)

	// Count the hosts as well as the certs
	totalProcessedHosts := 0
	go countHosts(commChans.hostCountChan, &totalProcessedHosts)

	for !finishedFlag {
		certStat := <-commChans.countChan
		totalCertsProcessed += certStat.newCerts
		fmt.Printf("%7.3f%% [%"+digitsHostsNumber+"d/%d] %s \t%d certificates (+%d)\n",
			100.*float32(totalProcessedHosts)/float32(hostsNumber),
			totalProcessedHosts,
			hostsNumber,
			certStat.host,
			totalCertsProcessed,
			certStat.newCerts,
		)
	}
}

func countHosts(hostCountChan chan int, hostsCount *int) {
	for !finishedFlag {
		newHost := <-hostCountChan
		*hostsCount += newHost
	}
}
