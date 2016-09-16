package main

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
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
	certData    []byte
}

// CertData contains interesting parts of a certificate
type CertData struct {
	SubjectCN          string
	SubjectO           string
	SubjectOU          []string
	SubjectCountry     []string
	IssuerCN           string
	IssuerO            string
	IssuerOU           []string
	IssuerCountry      []string
	NotBefore          time.Time
	NotAfter           time.Time
	FingerprintSHA1    string
	SignatureAlgorithm string
	SerialNumber       *big.Int
	X509Version        int
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

	if configOptions.verbose {
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

		if configOptions.verbose {
			fmt.Printf("> Trying IP %s\n", certprobe.IP)
		}

		// If we are dealing with IPv6, we need to add brackets.
		var addr string
		if ips[i].To4() != nil {
			// This is an IPv4 host

			if configOptions.IPv6only {
				continue // Do not process this host
			}

			addr = ips[i].String()
		} else {
			// This is an IPv6 host

			if configOptions.IPv4only {
				continue // Do not process this host
			}

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

		// Cipher suite
		cipherSuite := cstate.CipherSuite

		if configOptions.verbose {
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
				protocol = "something quite strange I've never seen before ("
			}

			fmt.Printf("Server used %s (ciphersuite %d) and sent %d certificates:\n", protocol, cipherSuite, len(certs))
		}

		// Count the certificates
		commChans.countChan <- CertStat{host, len(certs)}

		// Analyze presented certificates
		for id := 0; id < len(certs); id++ {
			if configOptions.verbose {
				PrintCertificate(certs[id])
			}

			// (Re)build the object
			certprobe.protocol = cstate.Version
			certprobe.cipherSuite = cipherSuite
			certprobe.certID = id
			certprobe.cert = certs[id]
			// Extract the useful data
			certDataAsByte, err := json.Marshal(certprobe.extractData())
			checkErr(err)
			certprobe.certData = certDataAsByte

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

func (cert certProbe) extractData() CertData {
	var cdata CertData
	cdata.SubjectCN = cert.cert.Subject.CommonName
	// cdata.SerialNumber = cert.cert.Subject.SerialNumber !?
	cdata.SubjectO = extractFromArray(cert.cert.Subject.Organization)
	cdata.SubjectOU = cert.cert.Subject.OrganizationalUnit
	cdata.SubjectCountry = cert.cert.Subject.Country

	cdata.X509Version = cert.cert.Version
	cdata.SerialNumber = cert.cert.SerialNumber

	// WTF: https://golang.org/src/crypto/x509/x509.go?s=4230:4257#L150
	// Method String should work...
	// cdata.SignatureAlgorithm = cert.cert.SignatureAlgorithm.String()

	der, err := x509.MarshalPKIXPublicKey(cert.cert.PublicKey)
	if err != nil {
		log.Printf("Public key algorithm: %s\n", cert.cert.PublicKeyAlgorithm)
		log.Println("Failed to extract the fingerprint :'(")
	} else {
		fingerprint := sha1.Sum(der)
		cdata.FingerprintSHA1 = hex.EncodeToString(fingerprint[:])
	}

	cdata.NotAfter = cert.cert.NotAfter

	cdata.IssuerCN = cert.cert.Issuer.CommonName
	cdata.IssuerO = extractFromArray(cert.cert.Issuer.Organization)
	cdata.IssuerOU = cert.cert.Issuer.OrganizationalUnit
	cdata.IssuerCountry = cert.cert.Issuer.Country

	return cdata
}

func extractFromArray(values []string) string {
	if len(values) == 1 {
		return values[0]
	} else if len(values) == 0 {
		return ""
	} else {
		log.Printf("Unable to analyze the following array (len=%d): \n%s", len(values), strings.Join(values, "\n"))
		log.Printf("Joining lines with newlines")
//panic("More than one element in the array")
		return strings.Join(values, "\n")
	}
}
