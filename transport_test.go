package libp2pwebtransport_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	libp2pwebtransport "github.com/marten-seemann/go-libp2p-webtransport"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"

	"github.com/golang/mock/gomock"
	mocknetwork "github.com/libp2p/go-libp2p-testing/mocks/network"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"

	"github.com/stretchr/testify/require"
)

func newIdentity(t *testing.T) (peer.ID, ic.PrivKey) {
	key, _, err := ic.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	id, err := peer.IDFromPrivateKey(key)
	require.NoError(t, err)
	return id, key
}

func randomMultihash(t *testing.T) string {
	b := make([]byte, 16)
	rand.Read(b)
	s, err := multibase.Encode(multibase.Base32hex, b)
	require.NoError(t, err)
	return s
}

func extractCertHashes(addr ma.Multiaddr) []string {
	var certHashesStr []string
	ma.ForEach(addr, func(c ma.Component) bool {
		if c.Protocol().Code == ma.P_CERTHASH {
			certHashesStr = append(certHashesStr, c.Value())
		}
		return true
	})
	return certHashesStr
}

func stripCertHashes(addr ma.Multiaddr) ma.Multiaddr {
	for {
		_, err := addr.ValueForProtocol(ma.P_CERTHASH)
		if err != nil {
			return addr
		}
		addr, _ = ma.SplitLast(addr)
	}
}

func TestTransport(t *testing.T) {
	serverID, serverKey := newIdentity(t)
	tr, err := libp2pwebtransport.New(serverKey, nil, network.NullResourceManager)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()
	ln, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)
	defer ln.Close()

	addrChan := make(chan ma.Multiaddr)
	go func() {
		_, clientKey := newIdentity(t)
		tr2, err := libp2pwebtransport.New(clientKey, nil, network.NullResourceManager)
		require.NoError(t, err)
		defer tr2.(io.Closer).Close()

		conn, err := tr2.Dial(context.Background(), ln.Multiaddr(), serverID)
		require.NoError(t, err)
		str, err := conn.OpenStream(context.Background())
		require.NoError(t, err)
		_, err = str.Write([]byte("foobar"))
		require.NoError(t, err)
		require.NoError(t, str.Close())

		// check RemoteMultiaddr
		_, addr, err := manet.DialArgs(ln.Multiaddr())
		require.NoError(t, err)
		_, port, err := net.SplitHostPort(addr)
		require.NoError(t, err)
		require.Equal(t, ma.StringCast(fmt.Sprintf("/ip4/127.0.0.1/udp/%s/quic/webtransport", port)), conn.RemoteMultiaddr())
		addrChan <- conn.RemoteMultiaddr()
	}()

	conn, err := ln.Accept()
	require.NoError(t, err)
	require.False(t, conn.IsClosed())
	str, err := conn.AcceptStream()
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, "foobar", string(data))
	require.Equal(t, <-addrChan, conn.LocalMultiaddr())
	require.NoError(t, conn.Close())
	require.True(t, conn.IsClosed())
}

func TestHashVerification(t *testing.T) {
	serverID, serverKey := newIdentity(t)
	tr, err := libp2pwebtransport.New(serverKey, nil, network.NullResourceManager)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()
	ln, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := ln.Accept()
		require.Error(t, err)
	}()

	_, clientKey := newIdentity(t)
	tr2, err := libp2pwebtransport.New(clientKey, nil, network.NullResourceManager)
	require.NoError(t, err)
	defer tr2.(io.Closer).Close()

	// create a hash component using the SHA256 of foobar
	h := sha256.Sum256([]byte("foobar"))
	mh, err := multihash.Encode(h[:], multihash.SHA2_256)
	require.NoError(t, err)
	certStr, err := multibase.Encode(multibase.Base58BTC, mh)
	require.NoError(t, err)
	foobarHash, err := ma.NewComponent(ma.ProtocolWithCode(ma.P_CERTHASH).Name, certStr)
	require.NoError(t, err)

	t.Run("fails using only a wrong hash", func(t *testing.T) {
		// replace the certificate hash in the multiaddr with a fake hash
		addr, _ := ma.SplitLast(ln.Multiaddr())
		addr = addr.Encapsulate(foobarHash)

		_, err := tr2.Dial(context.Background(), addr, serverID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "CRYPTO_ERROR (0x12a): cert hash not found")
	})

	t.Run("fails when adding a wrong hash", func(t *testing.T) {
		_, err := tr2.Dial(context.Background(), ln.Multiaddr().Encapsulate(foobarHash), serverID)
		require.Error(t, err)
	})

	require.NoError(t, ln.Close())
	<-done
}

func TestCanDial(t *testing.T) {
	valid := []ma.Multiaddr{
		ma.StringCast("/ip4/127.0.0.1/udp/1234/quic/webtransport/certhash/" + randomMultihash(t)),
		ma.StringCast("/ip6/b16b:8255:efc6:9cd5:1a54:ee86:2d7a:c2e6/udp/1234/quic/webtransport/certhash/" + randomMultihash(t)),
		ma.StringCast(fmt.Sprintf("/ip4/127.0.0.1/udp/1234/quic/webtransport/certhash/%s/certhash/%s/certhash/%s", randomMultihash(t), randomMultihash(t), randomMultihash(t))),
	}

	invalid := []ma.Multiaddr{
		ma.StringCast("/ip4/127.0.0.1/udp/1234"),                   // missing webtransport
		ma.StringCast("/ip4/127.0.0.1/udp/1234/webtransport"),      // missing quic
		ma.StringCast("/ip4/127.0.0.1/tcp/1234/webtransport"),      // WebTransport over TCP? Is this a joke?
		ma.StringCast("/ip4/127.0.0.1/udp/1234/quic/webtransport"), // missing certificate hash
	}

	_, key := newIdentity(t)
	tr, err := libp2pwebtransport.New(key, nil, network.NullResourceManager)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()

	for _, addr := range valid {
		require.Truef(t, tr.CanDial(addr), "expected to be able to dial %s", addr)
	}
	for _, addr := range invalid {
		require.Falsef(t, tr.CanDial(addr), "expected to not be able to dial %s", addr)
	}
}

func TestListenAddrValidity(t *testing.T) {
	valid := []ma.Multiaddr{
		ma.StringCast("/ip6/::/udp/0/quic/webtransport/"),
		ma.StringCast("/ip4/127.0.0.1/udp/1234/quic/webtransport/"),
	}

	invalid := []ma.Multiaddr{
		ma.StringCast("/ip4/127.0.0.1/udp/1234"),              // missing webtransport
		ma.StringCast("/ip4/127.0.0.1/udp/1234/webtransport"), // missing quic
		ma.StringCast("/ip4/127.0.0.1/tcp/1234/webtransport"), // WebTransport over TCP? Is this a joke?
		ma.StringCast("/ip4/127.0.0.1/udp/1234/quic/webtransport/certhash/" + randomMultihash(t)),
	}

	_, key := newIdentity(t)
	tr, err := libp2pwebtransport.New(key, nil, network.NullResourceManager)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()

	for _, addr := range valid {
		ln, err := tr.Listen(addr)
		require.NoErrorf(t, err, "expected to be able to listen on %s", addr)
		ln.Close()
	}
	for _, addr := range invalid {
		_, err := tr.Listen(addr)
		require.Errorf(t, err, "expected to not be able to listen on %s", addr)
	}
}

func TestListenerAddrs(t *testing.T) {
	_, key := newIdentity(t)
	tr, err := libp2pwebtransport.New(key, nil, network.NullResourceManager)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()

	ln1, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)
	ln2, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)
	hashes1 := extractCertHashes(ln1.Multiaddr())
	require.Len(t, hashes1, 1)
	hashes2 := extractCertHashes(ln2.Multiaddr())
	require.Equal(t, hashes1, hashes2)
}

func TestResourceManagerDialing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	rcmgr := mocknetwork.NewMockResourceManager(ctrl)

	addr := ma.StringCast("/ip4/9.8.7.6/udp/1234/quic/webtransport")
	p := peer.ID("foobar")

	_, key := newIdentity(t)
	tr, err := libp2pwebtransport.New(key, nil, rcmgr)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()

	scope := mocknetwork.NewMockConnManagementScope(ctrl)
	rcmgr.EXPECT().OpenConnection(network.DirOutbound, false, addr).Return(scope, nil)
	scope.EXPECT().SetPeer(p).Return(errors.New("denied"))
	scope.EXPECT().Done()

	_, err = tr.Dial(context.Background(), addr, p)
	require.EqualError(t, err, "denied")
}

func TestResourceManagerListening(t *testing.T) {
	clientID, key := newIdentity(t)
	cl, err := libp2pwebtransport.New(key, nil, network.NullResourceManager)
	require.NoError(t, err)
	defer cl.(io.Closer).Close()

	t.Run("blocking the connection", func(t *testing.T) {
		serverID, key := newIdentity(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		rcmgr := mocknetwork.NewMockResourceManager(ctrl)
		tr, err := libp2pwebtransport.New(key, nil, rcmgr)
		require.NoError(t, err)
		ln, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
		require.NoError(t, err)
		defer ln.Close()

		rcmgr.EXPECT().OpenConnection(network.DirInbound, false, gomock.Any()).DoAndReturn(func(_ network.Direction, _ bool, addr ma.Multiaddr) (network.ConnManagementScope, error) {
			_, err := addr.ValueForProtocol(ma.P_WEBTRANSPORT)
			require.NoError(t, err, "expected a WebTransport multiaddr")
			_, addrStr, err := manet.DialArgs(addr)
			require.NoError(t, err)
			host, _, err := net.SplitHostPort(addrStr)
			require.NoError(t, err)
			require.Equal(t, "127.0.0.1", host)
			return nil, errors.New("denied")
		})

		_, err = cl.Dial(context.Background(), ln.Multiaddr(), serverID)
		require.EqualError(t, err, "received status 503")
	})

	t.Run("blocking the peer", func(t *testing.T) {
		serverID, key := newIdentity(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		rcmgr := mocknetwork.NewMockResourceManager(ctrl)
		tr, err := libp2pwebtransport.New(key, nil, rcmgr)
		require.NoError(t, err)
		ln, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
		require.NoError(t, err)
		defer ln.Close()

		scope := mocknetwork.NewMockConnManagementScope(ctrl)
		rcmgr.EXPECT().OpenConnection(network.DirInbound, false, gomock.Any()).Return(scope, nil)
		scope.EXPECT().SetPeer(clientID).Return(errors.New("denied"))
		scope.EXPECT().Done()

		// The handshake will complete, but the server will immediately close the connection.
		conn, err := cl.Dial(context.Background(), ln.Multiaddr(), serverID)
		require.NoError(t, err)
		defer conn.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, err = conn.AcceptStream()
			require.Error(t, err)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	})
}

// TODO: unify somehow. We do the same in libp2pquic.
//go:generate sh -c "mockgen -package libp2pwebtransport_test -destination mock_connection_gater_test.go github.com/libp2p/go-libp2p-core/connmgr ConnectionGater && goimports -w mock_connection_gater_test.go"

func TestConnectionGaterDialing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	connGater := NewMockConnectionGater(ctrl)

	serverID, serverKey := newIdentity(t)
	tr, err := libp2pwebtransport.New(serverKey, nil, network.NullResourceManager)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()
	ln, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)
	defer ln.Close()

	connGater.EXPECT().InterceptSecured(network.DirOutbound, serverID, gomock.Any()).Do(func(_ network.Direction, _ peer.ID, addrs network.ConnMultiaddrs) {
		require.Equal(t, stripCertHashes(ln.Multiaddr()), addrs.RemoteMultiaddr())
	})
	_, key := newIdentity(t)
	cl, err := libp2pwebtransport.New(key, connGater, network.NullResourceManager)
	require.NoError(t, err)
	defer cl.(io.Closer).Close()
	_, err = cl.Dial(context.Background(), ln.Multiaddr(), serverID)
	require.EqualError(t, err, "secured connection gated")
}

func TestConnectionGaterInterceptAccept(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	connGater := NewMockConnectionGater(ctrl)

	serverID, serverKey := newIdentity(t)
	tr, err := libp2pwebtransport.New(serverKey, connGater, network.NullResourceManager)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()
	ln, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)
	defer ln.Close()

	connGater.EXPECT().InterceptAccept(gomock.Any()).Do(func(addrs network.ConnMultiaddrs) {
		require.Equal(t, stripCertHashes(ln.Multiaddr()), addrs.LocalMultiaddr())
		require.NotEqual(t, stripCertHashes(ln.Multiaddr()), addrs.RemoteMultiaddr())
	})

	_, key := newIdentity(t)
	cl, err := libp2pwebtransport.New(key, nil, network.NullResourceManager)
	require.NoError(t, err)
	defer cl.(io.Closer).Close()
	_, err = cl.Dial(context.Background(), ln.Multiaddr(), serverID)
	require.EqualError(t, err, "received status 403")
}

func TestConnectionGaterInterceptSecured(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	connGater := NewMockConnectionGater(ctrl)

	serverID, serverKey := newIdentity(t)
	tr, err := libp2pwebtransport.New(serverKey, connGater, network.NullResourceManager)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()
	ln, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)
	defer ln.Close()

	clientID, key := newIdentity(t)
	cl, err := libp2pwebtransport.New(key, nil, network.NullResourceManager)
	require.NoError(t, err)
	defer cl.(io.Closer).Close()

	connGater.EXPECT().InterceptAccept(gomock.Any()).Return(true)
	connGater.EXPECT().InterceptSecured(network.DirInbound, clientID, gomock.Any()).Do(func(_ network.Direction, _ peer.ID, addrs network.ConnMultiaddrs) {
		require.Equal(t, stripCertHashes(ln.Multiaddr()), addrs.LocalMultiaddr())
		require.NotEqual(t, stripCertHashes(ln.Multiaddr()), addrs.RemoteMultiaddr())
	})
	// The handshake will complete, but the server will immediately close the connection.
	conn, err := cl.Dial(context.Background(), ln.Multiaddr(), serverID)
	require.NoError(t, err)
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err = conn.AcceptStream()
		require.Error(t, err)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}
