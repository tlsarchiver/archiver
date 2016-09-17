package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fingerprint represents a cryptographically strong unique
// identifier of a public key identity.
type Fingerprint []byte

// SHA1Fingerprint calculates a SHA1 digest of the SubjectPublicKeyInfo
// section of an X.509 certificate
func SHA1Fingerprint(cert *x509.Certificate) Fingerprint {
	h := sha1.New()
	h.Write(cert.RawSubjectPublicKeyInfo)
	return Fingerprint(h.Sum(nil))
}

// String represents the fingerprint digest as a series of
// colon-delimited hexadecimal octets.
func (f Fingerprint) String() string {
	var buf bytes.Buffer
	for i, b := range f {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", b)
	}
	return buf.String()
}

// ParseFingerprint parses a colon-delimited series of hexadecimal octets.
func ParseFingerprint(fp string) (Fingerprint, error) {
	s := strings.Join(strings.Split(fp, ":"), "")
	buf, err := hex.DecodeString(s)
	return Fingerprint(buf), err
}
