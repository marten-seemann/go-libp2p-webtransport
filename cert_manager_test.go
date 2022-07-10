package libp2pwebtransport

import (
	"crypto/sha256"
	"crypto/tls"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"
)

func certificateHashFromTLSConfig(c *tls.Config) [32]byte {
	return sha256.Sum256(c.Certificates[0].Certificate[0])
}

func splitMultiaddr(addr ma.Multiaddr) []ma.Component {
	var components []ma.Component
	ma.ForEach(addr, func(c ma.Component) bool {
		components = append(components, c)
		return true
	})
	return components
}

func certHashFromComponent(t *testing.T, comp ma.Component) []byte {
	t.Helper()
	_, data, err := multibase.Decode(comp.Value())
	require.NoError(t, err)
	mh, err := multihash.Decode(data)
	require.NoError(t, err)
	require.Equal(t, uint64(multihash.SHA2_256), mh.Code)
	return mh.Digest
}

func TestInitialCert(t *testing.T) {
	cl := clock.NewMock()
	cl.Add(1234567 * time.Hour)
	m, err := newCertManager(cl)
	require.NoError(t, err)
	defer m.Close()

	conf := m.GetConfig()
	require.Len(t, conf.Certificates, 1)
	cert := conf.Certificates[0]
	require.Equal(t, cl.Now().UTC(), cert.Leaf.NotBefore)
	require.Equal(t, cl.Now().Add(certValidity).UTC(), cert.Leaf.NotAfter)
	addr := m.AddrComponent()
	components := splitMultiaddr(addr)
	require.Len(t, components, 1)
	require.Equal(t, ma.P_CERTHASH, components[0].Protocol().Code)
	hash := certificateHashFromTLSConfig(conf)
	require.Equal(t, hash[:], certHashFromComponent(t, components[0]))
}

func TestCertRenewal(t *testing.T) {
	cl := clock.NewMock()
	m, err := newCertManager(cl)
	require.NoError(t, err)
	defer m.Close()

	firstConf := m.GetConfig()
	require.Len(t, splitMultiaddr(m.AddrComponent()), 1)
	// wait for a new certificate to be generated
	cl.Add(certValidity / 2)
	require.Eventually(t, func() bool { return len(splitMultiaddr(m.AddrComponent())) > 1 }, 200*time.Millisecond, 10*time.Millisecond)
	// the actual config used should still be the same, we're just advertising the hash of the next config
	components := splitMultiaddr(m.AddrComponent())
	require.Len(t, components, 2)
	for _, c := range components {
		require.Equal(t, ma.P_CERTHASH, c.Protocol().Code)
	}
	require.Equal(t, firstConf, m.GetConfig())
	cl.Add(certValidity / 2)
	require.Eventually(t, func() bool { return m.GetConfig() != firstConf }, 200*time.Millisecond, 10*time.Millisecond)
	newConf := m.GetConfig()
	// check that the new config now matches the second component
	hash := certificateHashFromTLSConfig(newConf)
	require.Equal(t, hash[:], certHashFromComponent(t, components[1]))
}
