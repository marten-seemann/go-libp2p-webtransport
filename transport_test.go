package libp2pwebtransport_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"

	libp2pwebtransport "github.com/marten-seemann/go-libp2p-webtransport"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"

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

func extractCertHashes(t *testing.T, addr ma.Multiaddr) []string {
	var certHashesStr []string
	ma.ForEach(addr, func(c ma.Component) bool {
		if c.Protocol().Code == ma.P_CERTHASH {
			certHashesStr = append(certHashesStr, c.Value())
		}
		return true
	})
	return certHashesStr
}

func TestTransport(t *testing.T) {
	serverID, serverKey := newIdentity(t)
	tr, err := libp2pwebtransport.New(serverKey)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()
	ln, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)
	defer ln.Close()

	addrChan := make(chan ma.Multiaddr)
	go func() {
		_, clientKey := newIdentity(t)
		tr2, err := libp2pwebtransport.New(clientKey)
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
		port := strings.Split(addr, ":")[1]
		require.Equal(t, ma.StringCast(fmt.Sprintf("/ip4/127.0.0.1/udp/%s/quic/webtransport", port)), conn.RemoteMultiaddr())
		addrChan <- conn.RemoteMultiaddr()
	}()

	conn, err := ln.Accept()
	require.NoError(t, err)
	str, err := conn.AcceptStream()
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, "foobar", string(data))
	require.Equal(t, <-addrChan, conn.LocalMultiaddr())
}

func TestHashVerification(t *testing.T) {
	serverID, serverKey := newIdentity(t)
	tr, err := libp2pwebtransport.New(serverKey)
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
	tr2, err := libp2pwebtransport.New(clientKey)
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
	tr, err := libp2pwebtransport.New(key)
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
	tr, err := libp2pwebtransport.New(key)
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
	tr, err := libp2pwebtransport.New(key)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()

	ln1, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)
	ln2, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic/webtransport"))
	require.NoError(t, err)
	hashes1 := extractCertHashes(t, ln1.Multiaddr())
	require.Len(t, hashes1, 1)
	hashes2 := extractCertHashes(t, ln2.Multiaddr())
	require.Equal(t, hashes1, hashes2)
}
