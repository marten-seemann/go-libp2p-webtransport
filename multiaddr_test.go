package libp2pwebtransport

import (
	"net"
	"testing"

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
