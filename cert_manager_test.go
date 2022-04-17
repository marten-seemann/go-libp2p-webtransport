package libp2pwebtransport

import (
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

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
	m, err := newCertManager(certValidity)
	require.NoError(t, err)
	defer m.Close()

	conf := m.GetConfig()
	require.Len(t, conf.Certificates, 1)
	cert := conf.Certificates[0]
	require.WithinDuration(t, time.Now(), cert.Leaf.NotBefore, time.Second)
	require.WithinDuration(t, time.Now().Add(certValidity), cert.Leaf.NotAfter, time.Second)
	addr := m.AddrComponent()
	components := splitMultiaddr(addr)
	require.Len(t, components, 1)
	require.Equal(t, ma.P_CERTHASH, components[0].Protocol().Code)
	hash := certificateHash(conf)
	require.Equal(t, hash[:], certHashFromComponent(t, components[0]))
}

func TestCertRenewal(t *testing.T) {
	const certValidity = 300 * time.Millisecond
	m, err := newCertManager(certValidity)
	require.NoError(t, err)
	defer m.Close()

	firstConf := m.GetConfig()
	require.Len(t, splitMultiaddr(m.AddrComponent()), 1)
	// wait for a new certificate to be generated
	require.Eventually(t, func() bool { return len(splitMultiaddr(m.AddrComponent())) > 1 }, certValidity/2, 10*time.Millisecond)
	// the actual config used should still be the same, we're just advertising the hash of the next config
	components := splitMultiaddr(m.AddrComponent())
	require.Len(t, components, 2)
	for _, c := range components {
		require.Equal(t, ma.P_CERTHASH, c.Protocol().Code)
	}
	require.Equal(t, firstConf, m.GetConfig())
	require.Eventually(t, func() bool { return m.GetConfig() != firstConf }, certValidity/2, 10*time.Millisecond)
	newConf := m.GetConfig()
	// check that the new config now matches the second component
	hash := certificateHash(newConf)
	require.Equal(t, hash[:], certHashFromComponent(t, components[1]))
}
