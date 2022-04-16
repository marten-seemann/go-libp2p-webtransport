package libp2pwebtransport_test

import (
	"context"
	"crypto/rand"
	"io"
	"testing"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"

	libp2pwebtransport "github.com/marten-seemann/go-libp2p-webtransport"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestTransport(t *testing.T) {
	serverKey, _, err := ic.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	serverID, err := peer.IDFromPrivateKey(serverKey)
	require.NoError(t, err)
	tr, err := libp2pwebtransport.New(serverKey)
	require.NoError(t, err)
	ln, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)

	go func() {
		clientKey, _, err := ic.GenerateEd25519Key(rand.Reader)
		require.NoError(t, err)
		tr2, err := libp2pwebtransport.New(clientKey)
		require.NoError(t, err)
		conn, err := tr2.Dial(context.Background(), ln.Multiaddr(), serverID)
		require.NoError(t, err)
		str, err := conn.OpenStream(context.Background())
		require.NoError(t, err)
		_, err = str.Write([]byte("foobar"))
		require.NoError(t, err)
		require.NoError(t, str.Close())
	}()

	conn, err := ln.Accept()
	require.NoError(t, err)
	str, err := conn.AcceptStream()
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, "foobar", string(data))
}
