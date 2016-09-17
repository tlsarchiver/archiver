package main

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestFingerprintingStringOperations checks that fingerprints can be converted to and from strings
func TestFingerprintingStringOperations(t *testing.T) {
	txtFingerprint := "32:45:0D:44:BD:21:9D:17:9C:D7:CE:3B:74:90:E8:A5:AD:58:FE:01"

	fingerprint, err := ParseFingerprint(txtFingerprint)
	checkErr(err)

	if fingerprint.String() != txtFingerprint {
		t.Error("The fingerprint don't match: expected", txtFingerprint, "and got", fingerprint.String())
	}
}

// TestSHA1Fingerprint checks the SHA1 fingerprinting function
func TestSHA1Fingerprint(t *testing.T) {

	// Some RAW certificate
	const certPEM = `
-----BEGIN CERTIFICATE-----
MIICkzCCAfwCCQCtjYryqJuFWTANBgkqhkiG9w0BAQUFADCBjTELMAkGA1UEBhMC
VVMxFTATBgNVBAgTDFNvbWVwcm92aW5jZTERMA8GA1UEBxMIU29tZXRvd24xDTAL
BgNVBAoTBG5vbmUxDTALBgNVBAsTBG5vbmUxEjAQBgNVBAMTCWxvY2FsaG9zdDEi
MCAGCSqGSIb3DQEJARYTd2VibWFzdGVyQGxvY2FsaG9zdDAeFw0xNTA4MjAxMTIx
MjdaFw00MzAxMDQxMTIxMjdaMIGNMQswCQYDVQQGEwJVUzEVMBMGA1UECBMMU29t
ZXByb3ZpbmNlMREwDwYDVQQHEwhTb21ldG93bjENMAsGA1UEChMEbm9uZTENMAsG
A1UECxMEbm9uZTESMBAGA1UEAxMJbG9jYWxob3N0MSIwIAYJKoZIhvcNAQkBFhN3
ZWJtYXN0ZXJAbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDO
RN/jOgt5lqKvOMqCHrj04FNFZ4yA3q/s7hix/aQASqtRrf2iMH92PG3eTFIw5qE2
jr9yNeSUWPAhmDT4UpHTOElIQpVRmJ7psdU/iRicqpN6H+mK9RmSYo9dqTpD9hW/
2yf0Lv2QdkHLmNclB6Dp55RpcyLz1RHN5zqNoGCDPwIDAQABMA0GCSqGSIb3DQEB
BQUAA4GBAAegTUyUbkbzD3u7XWAym2YVxYxQ4p/quvqvjj4ufZXaHS8PiklHK16V
lj1xWCh64LauS7OOu4ixml8cu0++fN1dgfRMn8diP2LGZ0Agk+fYwGYCm2P/mufk
xOlp8m+wzK110h5r32i8tFB2WDGeFtpjjOOvVZ8KMyOwUfWLs2WL
-----END CERTIFICATE-----
`

	// Decode the certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	// We now have a valid x509.Certificate object. Let's test our fingerprinting
	// function.

	// Get the computed fingerprint
	SHA1fingerprint := SHA1Fingerprint(cert)

	// Known fingerprint for the given certificate
	expectedFingerprint, err := ParseFingerprint("32:45:0D:44:BD:21:9D:17:9C:D7:CE:3B:74:90:E8:A5:AD:58:FE:01")
	checkErr(err)

	if SHA1fingerprint.String() == expectedFingerprint.String() {
		t.Error("The fingerprint don't match: ", SHA1fingerprint, " != ", expectedFingerprint)
	}
}
