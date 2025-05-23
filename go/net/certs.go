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

	// Create certificate dynamically
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

	// Create certificate for TLS
	certForTLS := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}

	// Construct ALPN identifier
	var alpnIdentifiers []string

	// Try all possible ALPN format variations
	alpnIdentifiers = append(alpnIdentifiers, "jamnp-s/0/dev")                        // Dev testnet format
	alpnIdentifiers = append(alpnIdentifiers, "jamnp-s/0/DEV")                        // Uppercase variant
	alpnIdentifiers = append(alpnIdentifiers, "jamnp-s")                              // Base protocol only
	alpnIdentifiers = append(alpnIdentifiers, "jamnp-s/dev")                          // Without version
	alpnIdentifiers = append(alpnIdentifiers, "jamnp-s/0")                            // Version only
	alpnIdentifiers = append(alpnIdentifiers, fmt.Sprintf("jamnp-s/0/%s", chainHash)) // With provided chain hash

	// Additional formats used by some implementations
	alpnIdentifiers = append(alpnIdentifiers, "jam")      // Just "jam"
	alpnIdentifiers = append(alpnIdentifiers, "jamnp")    // Just "jamnp"
	alpnIdentifiers = append(alpnIdentifiers, "polkajam") // Just "polkajam"
	alpnIdentifiers = append(alpnIdentifiers, "h3")       // HTTP/3 (some QUIC implementations default to this)

	log.Printf("Trying %d ALPN identifiers: %v", len(alpnIdentifiers), alpnIdentifiers)

	// In insecure mode, use a very minimal TLS config
	if insecure {
		log.Println("Using insecure TLS configuration")
		// For testing only - use the minimum TLS configuration that will work while still properly presenting our identity
		return &tls.Config{
			Certificates:       []tls.Certificate{certForTLS},
			NextProtos:         alpnIdentifiers,
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			// Still require server certificates, but don't validate them
			ClientAuth: tls.RequireAnyClientCert,
			// Do not attempt to verify the peer name
			VerifyConnection: func(tls.ConnectionState) error {
				return nil
			},
			// Use the default cipher suites
			CipherSuites: nil,
			// Add debug callback for TLS handshake
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				log.Println("Client verifying peer certificate in insecure mode (should always pass)")
				// Log the certificate details but don't reject
				if len(rawCerts) > 0 {
					cert, err := x509.ParseCertificate(rawCerts[0])
					if err == nil {
						log.Printf("Server certificate (not validated): Subject=%s, Issuer=%s",
							cert.Subject.CommonName, cert.Issuer.CommonName)
					}
				}
				return nil
			},
		}, nil
	}

	// Create TLS config for secure mode
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			certForTLS,
		},
		NextProtos:             alpnIdentifiers,
		MinVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519},
		SessionTicketsDisabled: true,
		// JAMNP-S requires client and server certificates
		ClientAuth: tls.RequireAnyClientCert,
		// Add detailed handshake callback for debugging
		VerifyConnection: func(state tls.ConnectionState) error {
			log.Printf("=== TLS HANDSHAKE COMPLETE ===")
			log.Printf("Protocol version: %x", state.Version)
			log.Printf("Cipher suite: %x", state.CipherSuite)
			log.Printf("Negotiated protocol: %s", state.NegotiatedProtocol)
			log.Printf("Server name: %s", state.ServerName)
			log.Printf("Peer certificates: %d", len(state.PeerCertificates))

			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				log.Printf("Peer certificate details:")
				log.Printf("  Subject: %s", cert.Subject.CommonName)
				log.Printf("  Issuer: %s", cert.Issuer.CommonName)
				log.Printf("  Valid from: %s", cert.NotBefore)
				log.Printf("  Valid until: %s", cert.NotAfter)
				log.Printf("  DNS names: %v", cert.DNSNames)

				if pubKey, ok := cert.PublicKey.(ed25519.PublicKey); ok {
					log.Printf("  Public key: %x", pubKey)
				}
			}

			return nil
		},
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
	log.Printf("Deserialized uint256 (hex): %s", n.Text(16))
	log.Printf("Deserialized uint256 (decimal): %s", n.String())

	// Serialize uint256 back to a 32-byte array
	serialized := serializeUint256(n)
	log.Printf("Serialized uint256: %x", serialized)

	// Apply the B(n, l) function with l=52
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var result strings.Builder
	result.WriteByte('e')

	// Generate 52 characters
	for i := 0; i < 52; i++ {
		// Get n mod 32 and write the corresponding character
		mod := new(big.Int).Mod(n, big.NewInt(32))
		modVal := mod.Int64()
		result.WriteByte(alphabet[modVal])

		// Integer division: n = floor(n / 32)
		n.Div(n, big.NewInt(32))
	}

	altName := result.String()
	log.Printf("Generated alternative name: %s", altName)

	return altName
}

// deserializeUint256 converts a 32-byte array to a big.Int (uint256)
// This implements the E^(-1)_32 deserialization function as defined in the GP
func deserializeUint256(data []byte) *big.Int {
	// Create a new big.Int
	result := new(big.Int)

	// Use the same approach as DecodeLittleEndian but for big.Int
	// For each byte, shift it to the appropriate position and OR it in
	for i, b := range data {
		// Convert byte to big.Int
		byteVal := big.NewInt(int64(b))

		// Shift the byte to its position (8*i bits)
		if i > 0 {
			byteVal.Lsh(byteVal, uint(8*i))
		}

		// OR it into the result
		result.Or(result, byteVal)
	}

	// Log the result for debugging
	log.Printf("Public key bytes: %x", data)
	log.Printf("Little-endian deserialize result: %s", result.Text(16))

	return result
}

// serializeUint256 converts a big.Int (uint256) to a 32-byte array
// This implements the E_32 serialization function as defined in the GP
func serializeUint256(n *big.Int) []byte {
	// Create a new 32-byte array
	result := make([]byte, 32)

	// Clone the big.Int to avoid modifying the original
	temp := new(big.Int).Set(n)

	// For each byte position
	for i := 0; i < 32; i++ {
		// Extract the lowest 8 bits
		byteVal := new(big.Int).And(temp, big.NewInt(0xFF))

		// Store the byte
		result[i] = byte(byteVal.Uint64())

		// Shift right by 8 bits for the next byte
		temp.Rsh(temp, 8)
	}

	return result
}
