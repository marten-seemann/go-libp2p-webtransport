package libp2pwebtransport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"
)

func sha256Multihash(t *testing.T, b []byte) multihash.DecodedMultihash {
	t.Helper()
	hash := sha256.Sum256(b)
	h, err := multihash.Encode(hash[:], multihash.SHA2_256)
	require.NoError(t, err)
	dh, err := multihash.Decode(h)
	require.NoError(t, err)
	return *dh
}

func generateCertWithKey(t *testing.T, key crypto.PrivateKey, start, end time.Time) *x509.Certificate {
	t.Helper()
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(mrand.Uint64())),
		Subject:               pkix.Name{},
		NotBefore:             start,
		NotAfter:              end,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, certTempl, key.(interface{ Public() crypto.PublicKey }).Public(), key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caBytes)
	require.NoError(t, err)
	return ca
}

func TestCertificateVerification(t *testing.T) {
	now := time.Now()
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	t.Run("accepting a valid cert", func(t *testing.T) {
		validCert := generateCertWithKey(t, ecdsaKey, now, now.Add(14*24*time.Hour))
		require.NoError(t, verifyRawCerts([][]byte{validCert.Raw}, []multihash.DecodedMultihash{sha256Multihash(t, validCert.Raw)}))
	})

	for _, tc := range [...]struct {
		name   string
		cert   *x509.Certificate
		errStr string
	}{
		{
			name:   "validitity period too long",
			cert:   generateCertWithKey(t, ecdsaKey, now, now.Add(15*24*time.Hour)),
			errStr: "cert must not be valid for longer than 14 days",
		},
		{
			name:   "uses RSA key",
			cert:   generateCertWithKey(t, rsaKey, now, now.Add(14*24*time.Hour)),
			errStr: "RSA",
		},
		{
			name:   "expired certificate",
			cert:   generateCertWithKey(t, ecdsaKey, now.Add(-14*24*time.Hour), now),
			errStr: "cert not valid",
		},
		{
			name:   "not yet valid",
			cert:   generateCertWithKey(t, ecdsaKey, now.Add(time.Hour), now.Add(time.Hour+14*24*time.Hour)),
			errStr: "cert not valid",
		},
	} {
		tc := tc
		t.Run(fmt.Sprintf("rejecting invalid certificates: %s", tc.name), func(t *testing.T) {
			err := verifyRawCerts([][]byte{tc.cert.Raw}, []multihash.DecodedMultihash{sha256Multihash(t, tc.cert.Raw)})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errStr)
		})
	}

	for _, tc := range [...]struct {
		name   string
		certs  [][]byte
		hashes []multihash.DecodedMultihash
		errStr string
	}{
		{
			name:   "no certificates",
			hashes: []multihash.DecodedMultihash{sha256Multihash(t, []byte("foobar"))},
			errStr: "no cert",
		},
		{
			name:   "certificate not parseable",
			certs:  [][]byte{[]byte("foobar")},
			hashes: []multihash.DecodedMultihash{sha256Multihash(t, []byte("foobar"))},
			errStr: "x509: malformed certificate",
		},
		{
			name:   "hash mismatch",
			certs:  [][]byte{generateCertWithKey(t, ecdsaKey, now, now.Add(15*24*time.Hour)).Raw},
			hashes: []multihash.DecodedMultihash{sha256Multihash(t, []byte("foobar"))},
			errStr: "cert hash not found",
		},
	} {
		tc := tc
		t.Run(fmt.Sprintf("rejecting invalid certificates: %s", tc.name), func(t *testing.T) {
			err := verifyRawCerts(tc.certs, tc.hashes)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errStr)
		})
	}
}
