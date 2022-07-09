package libp2pwebtransport

import (
	"fmt"
	"net"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"
)

func TestWebtransportMultiaddr(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		addr, err := toWebtransportMultiaddr(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337})
		require.NoError(t, err)
		require.Equal(t, "/ip4/127.0.0.1/udp/1337/quic/webtransport", addr.String())
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := toWebtransportMultiaddr(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337})
		require.EqualError(t, err, "not a UDP address")
	})
}

func TestWebtransportMultiaddrFromString(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		addr, err := stringToWebtransportMultiaddr("1.2.3.4:60042")
		require.NoError(t, err)
		require.Equal(t, "/ip4/1.2.3.4/udp/60042/quic/webtransport", addr.String())
	})

	t.Run("invalid", func(t *testing.T) {
		for _, addr := range [...]string{
			"1.2.3.4",        // missing port
			"1.2.3.4:123456", // invalid port
			":1234",          // missing IP
			"foobar",
		} {
			_, err := stringToWebtransportMultiaddr(addr)
			require.Error(t, err)
		}
	})
}

func encodeCertHash(t *testing.T, b []byte, mh uint64, mb multibase.Encoding) string {
	t.Helper()
	h, err := multihash.Encode(b, mh)
	require.NoError(t, err)
	str, err := multibase.Encode(mb, h)
	require.NoError(t, err)
	return str
}

func TestExtractCertHashes(t *testing.T) {
	fooHash := encodeCertHash(t, []byte("foo"), multihash.SHA2_256, multibase.Base58BTC)
	barHash := encodeCertHash(t, []byte("bar"), multihash.BLAKE2B_MAX, multibase.Base32)

	// valid cases
	for _, tc := range [...]struct {
		addr   string
		hashes []string
	}{
		{addr: "/ip4/127.0.0.1/udp/1234/quic/webtransport"},
		{addr: fmt.Sprintf("/ip4/127.0.0.1/udp/1234/quic/webtransport/certhash/%s", fooHash), hashes: []string{"foo"}},
		{addr: fmt.Sprintf("/ip4/127.0.0.1/udp/1234/quic/webtransport/certhash/%s/certhash/%s", fooHash, barHash), hashes: []string{"foo", "bar"}},
	} {
		ch, err := extractCertHashes(ma.StringCast(tc.addr))
		require.NoError(t, err)
		require.Len(t, ch, len(tc.hashes))
		for i, h := range tc.hashes {
			require.Equal(t, h, string(ch[i].Digest))
		}
	}

	// invalid cases
	for _, tc := range [...]struct {
		addr string
		err  string
	}{
		{addr: fmt.Sprintf("/ip4/127.0.0.1/udp/1234/quic/webtransport/certhash/%s", fooHash[:len(fooHash)-1]), err: "failed to multihash-decode certificate hash"},
	} {
		_, err := extractCertHashes(ma.StringCast(tc.addr))
		require.Error(t, err)
		require.Contains(t, err.Error(), tc.err)
	}
}
