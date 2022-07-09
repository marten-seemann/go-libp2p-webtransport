package libp2pwebtransport

import (
	"context"
	"fmt"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	tpt "github.com/libp2p/go-libp2p-core/transport"

	"github.com/marten-seemann/webtransport-go"
	ma "github.com/multiformats/go-multiaddr"
)

type conn struct {
	transport tpt.Transport
	session   *webtransport.Session

	localPeer, remotePeer peer.ID
	local, remote         ma.Multiaddr
	privKey               ic.PrivKey
	remotePubKey          ic.PubKey
	scope                 network.ConnScope
}

func newConn(tr tpt.Transport, sess *webtransport.Session, privKey ic.PrivKey, remotePubKey ic.PubKey, scope network.ConnScope) (*conn, error) {
	localPeer, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	remotePeer, err := peer.IDFromPublicKey(remotePubKey)
	if err != nil {
		return nil, err
	}
	local, err := toWebtransportMultiaddr(sess.LocalAddr())
	if err != nil {
		return nil, fmt.Errorf("error determiniting local addr: %w", err)
	}
	remote, err := toWebtransportMultiaddr(sess.RemoteAddr())
	if err != nil {
		return nil, fmt.Errorf("error determiniting remote addr: %w", err)
	}
	return &conn{
		transport:    tr,
		session:      sess,
		privKey:      privKey,
		localPeer:    localPeer,
		remotePeer:   remotePeer,
		remotePubKey: remotePubKey,
		local:        local,
		remote:       remote,
		scope:        scope,
	}, nil
}

var _ tpt.CapableConn = &conn{}

func (c *conn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	str, err := c.session.OpenStreamSync(ctx)
	return &stream{str}, err
}

func (c *conn) AcceptStream() (network.MuxedStream, error) {
	str, err := c.session.AcceptStream(context.Background())
	return &stream{str}, err
}

func (c *conn) Close() error                  { return c.session.Close() }
func (c *conn) IsClosed() bool                { return c.session.Context().Err() != nil }
func (c *conn) LocalPeer() peer.ID            { return c.localPeer }
func (c *conn) LocalPrivateKey() ic.PrivKey   { return c.privKey }
func (c *conn) RemotePeer() peer.ID           { return c.remotePeer }
func (c *conn) RemotePublicKey() ic.PubKey    { return c.remotePubKey }
func (c *conn) LocalMultiaddr() ma.Multiaddr  { return c.local }
func (c *conn) RemoteMultiaddr() ma.Multiaddr { return c.remote }
func (c *conn) Scope() network.ConnScope      { return c.scope }
func (c *conn) Transport() tpt.Transport      { return c.transport }
