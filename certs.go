package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"
)

type certProbe struct {
	host        string
	IP          string
	protocol    uint16
	cipherSuite uint16
	certID      int
	cert        *x509.Certificate
	failure     error
	timestamp   time.Time
}

// PrintCertificate prints the given certificate in a user-friendly way
func PrintCertificate(cert *x509.Certificate) {
	fmt.Printf("  %s%s C=%s/O=%s/OU=%s/CN=%s\n",
		cert.Subject.Names,
		cert.Subject.ExtraNames,
		cert.Subject.Country,
		cert.Subject.Organization,
		cert.Subject.OrganizationalUnit,
		cert.Subject.CommonName,
	)
}

func grabCert(host string, commChans CommChans) {

	if verbose {
		fmt.Printf("\nProbing server %s...\n", host)
	}

	// Build the probe object
	certprobe := certProbe{
		host:      host,
		timestamp: time.Now().UTC(),
	}

	// Resolve the hostname (get all IPv4 / v6 addresses)
	ips, err := net.LookupIP(host)
	// Unable to resolve the host? Log it.
	if err != nil {
		failProbe(certprobe, err, commChans)
		return
	}

	for i := 0; i < len(ips); i++ {
		// Now we know the IP
		certprobe.IP = ips[i].String()

		// If we are dealing with IPv6, we need to add brackets.
		var addr string
		if ips[i].To4() != nil {
			addr = ips[i].String()
		} else {
			addr = "[" + ips[i].String() + "]"
		}

		// Dring dring
		conn, err := tls.Dial("tcp", addr+":443", conf)

		// Unable to open the connection? Log it.
		if err != nil {
			failProbe(certprobe, err, commChans)
			return
		}

		// Close the connection when we are done with this host
		defer conn.Close()

		cstate := conn.ConnectionState()

		certs := cstate.PeerCertificates

		// Check if the handshake completed
		if !cstate.HandshakeComplete {
			fmt.Println("Handshake was not complete!!")
		}

		// Pretty-print the protocol
		var protocol string
		switch cstate.Version {
		case tls.VersionTLS12:
			protocol = "TLS 1.2"
		case tls.VersionTLS11:
			protocol = "TLS 1.1"
		case tls.VersionTLS10:
			protocol = "TLS 1.0"
		case tls.VersionSSL30:
			protocol = "SSL 3.0"
		default:
			protocol = "something quite strange I never seen before ("
		}

		// Cipher suite
		cipherSuite := cstate.CipherSuite

		if verbose {
			fmt.Printf("Server used %s (ciphersuite %d) and sent %d certificates:\n", protocol, cipherSuite, len(certs))
		}

		// Count the certificates
		commChans.countChan <- CertStat{host, len(certs)}

		// Analyze presented certificates
		for id := 0; id < len(certs); id++ {
			if verbose {
				PrintCertificate(certs[id])
			}

			// (Re)build the object
			certprobe.protocol = cstate.Version
			certprobe.protocol = cstate.Version
			certprobe.cipherSuite = cipherSuite
			certprobe.certID = id
			certprobe.cert = certs[id]

			// Send the certificate information into the tube
			commChans.certsChan <- certprobe
		}
	}
}

func failProbe(certprobe certProbe, err error, commChans CommChans) {
	certprobe.failure = err
	commChans.certsChan <- certprobe
	log.Println(err)
}
