package net

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// OIDs for certificate extensions
var (
	// OID for KeyUsage extension
	oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// AlternativeNameEncoding is the encoding used for the alternative name
const AlternativeNameEncoding = "abcdefghijklmnopqrstuvwxyz234567"

// generateTLSConfig creates a TLS configuration for the JAMNP-S client
func generateTLSConfig(
	privateKey ed25519.PrivateKey,
) (*tls.Config, error) {
	// Generate a self-signed certificate
	cert, err := generateCertificate(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // Require TLS 1.3
		// Custom verification to validate peer certificate
		VerifyPeerCertificate: verifyPeerCertificate,
	}

	return tlsConfig, nil
}

// generateCertificate creates a self-signed certificate for the JAMNP-S client
func generateCertificate(privateKey ed25519.PrivateKey) (tls.Certificate, error) {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	// Generate alternative name from public key
	altName, err := GenerateAlternativeName(publicKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate alternative name: %w", err)
	}

	// Generate a random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: altName,
		},
		DNSNames:    []string{altName},
		NotBefore:   time.Now().Add(-time.Hour),  // Valid from 1 hour ago
		NotAfter:    time.Now().AddDate(1, 0, 0), // Valid for 1 year
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		// KeyUsage field intentionally left empty - we'll add it manually as non-critical
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Important: Create a DER-encoded certificate without the standard KeyUsage field
	// We'll add it manually as a non-critical extension below
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate to add custom extensions
	_, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Add KeyUsage extension manually as non-critical
	keyUsageValue := x509.KeyUsageDigitalSignature // Same as would be added automatically
	keyUsageBytes, err := asn1.Marshal(keyUsageValue)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal key usage: %w", err)
	}

	// Create a new certificate with the custom extension
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:       oidKeyUsage,
			Critical: false, // Non-critical to avoid UnhandledCriticalExtension errors
			Value:    keyUsageBytes,
		},
	}

	// Create the certificate again with our custom extensions
	certBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate with extensions: %w", err)
	}

	// Create a tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privateKey,
	}

	return tlsCert, nil
}

// GenerateAlternativeName generates the alternative name for a certificate
// using the algorithm specified in the JAMNP-S protocol
func GenerateAlternativeName(pubKey ed25519.PublicKey) (string, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key size: %d", len(pubKey))
	}

	// Create a big.Int from the public key (little-endian)
	n := new(big.Int)
	// Reverse the bytes for little-endian interpretation
	revBytes := make([]byte, len(pubKey))
	for i, b := range pubKey {
		revBytes[len(pubKey)-1-i] = b
	}
	n.SetBytes(revBytes)

	// Generate the alternative name using the B function from spec
	result := "e" // Start with 'e' as per spec

	// Constants for the loop
	thirtytwo := big.NewInt(32)
	mod := new(big.Int)

	for i := 0; i < 52; i++ {
		// Get the remainder when divided by 32
		mod = mod.Mod(n, thirtytwo)
		idx := int(mod.Int64())
		result += string(AlternativeNameEncoding[idx])

		// Divide by 32 for the next iteration
		n.Div(n, thirtytwo)
	}

	return result, nil
}

// verifyPeerCertificate verifies that the peer's certificate follows the JAMNP-S spec
func verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificate provided by peer")
	}

	// Parse the peer's certificate
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse peer certificate: %w", err)
	}

	// Check that the certificate uses Ed25519
	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("peer certificate does not use Ed25519 key")
	}

	// Check that the certificate has exactly one DNS SANs
	if len(cert.DNSNames) != 1 {
		return fmt.Errorf("peer certificate must have exactly one DNS name, has %d",
			len(cert.DNSNames))
	}

	// Generate the expected alternative name
	expectedName, err := GenerateAlternativeName(publicKey)
	if err != nil {
		return fmt.Errorf("failed to generate expected name: %w", err)
	}

	// Verify the alternative name
	if cert.DNSNames[0] != expectedName {
		return fmt.Errorf("peer certificate DNS name does not match expected name: %s vs %s",
			cert.DNSNames[0], expectedName)
	}

	return nil
}
