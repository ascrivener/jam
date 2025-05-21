package net

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// generateTLSConfig creates a TLS config with a self-signed Ed25519 certificate
// according to the JAMNP-S specification
func generateTLSConfig(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey, version, chainHash string, isBuilder bool, insecure bool) (*tls.Config, error) {
	// Create certificate
	certDER, err := generateCertificate(pubKey, privKey)
	if err != nil {
		return nil, err
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

			for _, name := range cert.DNSNames {
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
func generateCertificate(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) ([]byte, error) {
	altName := generateAlternativeName(pubKey)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: altName,
		},
		DNSNames:              []string{altName},
		NotBefore:             time.Now().Add(-time.Hour),           // Allow for some clock skew
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	return x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
}

// generateAlternativeName computes the alternative name as specified in the protocol
// It implements the N(k) function from the specification
func generateAlternativeName(pubKey ed25519.PublicKey) string {
	// Deserialize public key to a uint256
	n := deserializeUint256(pubKey)

	// Apply the B(n, l) function with l=52
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var result strings.Builder
	result.WriteByte('$')
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
// This is a simplified version and may need adjustment depending on
// the exact deserialization function defined in the GP
func deserializeUint256(data []byte) *big.Int {
	// Make a copy to ensure we don't modify the original data
	buf := make([]byte, len(data))
	copy(buf, data)

	// Convert to little-endian if needed (the spec may require big-endian)
	// Adjust this based on the actual serialization codec in the GP

	return new(big.Int).SetBytes(buf)
}
