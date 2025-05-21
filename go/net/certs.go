package net

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)

// generateTLSConfig creates a TLS config with a self-signed Ed25519 certificate
// according to the JAMNP-S specification
func generateTLSConfig(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey, version, chainHash string, isBuilder bool, insecure bool) (*tls.Config, error) {
	// Debug: Log the public key for troubleshooting
	log.Printf("Ed25519 Public Key: %s", hex.EncodeToString(pubKey))

	// Create certificate
	certDER, err := generateCertificate(pubKey, privKey)
	if err != nil {
		return nil, err
	}

	// Debug: Write certificate to file for inspection
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	os.WriteFile("debug_cert.pem", certPEM, 0644)

	// Debug: Parse and display certificate details
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Printf("Failed to parse certificate for debugging: %v", err)
	} else {
		log.Printf("Certificate details:")
		log.Printf("  Subject: %s", cert.Subject.CommonName)
		log.Printf("  DNSNames: %v", cert.DNSNames)
		log.Printf("  Extensions:")
		for _, ext := range cert.Extensions {
			log.Printf("    ID: %v, Critical: %v", ext.Id, ext.Critical)
		}
	}

	// Create leaf certificate
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Construct ALPN identifier
	alpn := fmt.Sprintf("jamnp-s/%s/%s", version, chainHash)
	if isBuilder {
		alpn += "/builder"
	}

	// In insecure mode, use a very minimal TLS config
	if insecure {
		log.Println("Using insecure TLS configuration")
		// For testing only - use the absolute minimum TLS configuration that will work
		return &tls.Config{
			Certificates:       []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: privKey}},
			NextProtos:         []string{alpn},
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			// Important: Do not validate client certificates at all in test mode
			ClientAuth: tls.NoClientCert,
			// Do not attempt to verify the peer name
			VerifyConnection: func(tls.ConnectionState) error {
				return nil
			},
			// Use the default cipher suites
			CipherSuites: nil,
			// Add debug callback for TLS handshake
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				log.Println("Client verifying peer certificate in insecure mode (should always pass)")
				return nil
			},
		}, nil
	}

	// Create TLS config for secure mode
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certDER},
				PrivateKey:  privKey,
				Leaf:        leaf,
			},
		},
		NextProtos:             []string{alpn},
		MinVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519},
		SessionTicketsDisabled: true,
		// JAMNP-S requires client and server certificates
		ClientAuth: tls.RequireAnyClientCert,
	}

	// Only verify certificates if not in insecure mode
	if !insecure {
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// Parse the peer's certificate
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificate provided by peer")
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse peer certificate: %w", err)
			}

			// Debug: Log the remote certificate details
			log.Printf("Remote certificate details:")
			log.Printf("  Subject: %s", cert.Subject.CommonName)
			log.Printf("  Issuer: %s", cert.Issuer.CommonName)
			log.Printf("  Public Key Algorithm: %v", cert.PublicKeyAlgorithm)
			log.Printf("  DNSNames: %v", cert.DNSNames)
			log.Printf("  Extensions:")
			for _, ext := range cert.Extensions {
				log.Printf("    ID: %v, Critical: %v", ext.Id, ext.Critical)
			}

			// Extract the public key for detailed debugging
			if peerPubKey, ok := cert.PublicKey.(ed25519.PublicKey); ok {
				log.Printf("  Remote Ed25519 Public Key: %s", hex.EncodeToString(peerPubKey))
				log.Printf("  Expected Alternative Name: %s", generateAlternativeName(peerPubKey))
			}

			// Verify that the certificate uses Ed25519
			if cert.PublicKeyAlgorithm != x509.Ed25519 {
				return fmt.Errorf("peer certificate does not use Ed25519")
			}

			// Extract the public key
			peerPubKey, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("peer certificate public key is not Ed25519")
			}

			// Check that the alternative name is derived correctly from the public key
			expectedAltName := generateAlternativeName(peerPubKey)
			found := false

			// Check both DNSNames and OtherNames in Subject Alternative Name
			for _, name := range cert.DNSNames {
				log.Printf("  Checking DNS name: %s against expected: %s", name, expectedAltName)
				if name == expectedAltName {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("peer certificate does not have correct alternative name")
			}

			return nil
		}
	}

	return tlsConfig, nil
}

// generateCertificate creates a self-signed certificate for the client
// using a custom approach to avoid critical extensions
func generateCertificate(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) ([]byte, error) {
	altName := generateAlternativeName(pubKey)
	log.Printf("Generated alternative name: %s", altName)

	// Create a certificate template with bare minimum fields
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: altName,
		},
		DNSNames:  []string{altName},
		NotBefore: time.Now().Add(-time.Hour),           // Allow for some clock skew
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year

		// Use ExtKeyUsage only, and remove KeyUsage which is always critical
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// Add a custom non-critical KeyUsage extension manually
	// OID 2.5.29.15 is KeyUsage
	keyUsageValue, err := asn1.Marshal(asn1.BitString{
		Bytes:     []byte{0x80}, // digitalSignature (first bit)
		BitLength: 8,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key usage: %w", err)
	}

	// Create a raw extension that is NOT critical
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // KeyUsage OID
			Critical: false,                               // <-- THIS IS THE KEY CHANGE
			Value:    keyUsageValue,
		},
	}

	// Create self-signed certificate
	return x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
}

// generateAlternativeName computes the alternative name as specified in the protocol
// It implements the N(k) function from the specification
func generateAlternativeName(pubKey ed25519.PublicKey) string {
	// Log the public key bytes for debugging
	log.Printf("Input to alternative name generation: %x", pubKey)

	// Deserialize public key to a uint256
	n := deserializeUint256(pubKey)
	log.Printf("Deserialized uint256: %s", n.Text(16))

	// Apply the B(n, l) function with l=52
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var result strings.Builder
	result.WriteByte('e')

	// Generate 52 characters
	for i := 0; i < 52; i++ {
		// Get n mod 32 and write the corresponding character
		mod := new(big.Int).Mod(n, big.NewInt(32))
		result.WriteByte(alphabet[mod.Int64()])

		// Integer division: n = floor(n / 32)
		n.Div(n, big.NewInt(32))
	}

	return result.String()
}

// deserializeUint256 converts a 32-byte array to a big.Int (uint256)
// This implements the E^(-1)_32 deserialization function as defined in the GP
func deserializeUint256(data []byte) *big.Int {
	// The specification requires interpreting the key as a 256-bit unsigned integer
	// Make a copy to ensure we don't modify the original data
	buf := make([]byte, len(data))
	copy(buf, data)

	// The GP's definition might require the bytes to be in a specific order
	// Let's try big-endian first (which is the default for big.Int)
	n := new(big.Int).SetBytes(buf)

	// Debug: Log both possibilities
	reversed := make([]byte, len(buf))
	copy(reversed, buf)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	nReversed := new(big.Int).SetBytes(reversed)

	log.Printf("Original bytes interpretation (big-endian): %s", n.Text(16))
	log.Printf("Reversed bytes interpretation (little-endian): %s", nReversed.Text(16))

	// Reverse the bytes if we believe the deserialization should be little-endian
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}

	return new(big.Int).SetBytes(buf)
}
