package libp2pwebtransport

import (
	"context"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	tpt "github.com/libp2p/go-libp2p-core/transport"
	"github.com/marten-seemann/webtransport-go"
	ma "github.com/multiformats/go-multiaddr"
)

type conn struct {
	transport tpt.Transport
	wconn     *webtransport.Conn
}

var _ tpt.CapableConn = &conn{}

func (c *conn) Close() error {
	return c.wconn.Close()
}

func (c *conn) IsClosed() bool {
	panic("implement me")
}

func (c *conn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	str, err := c.wconn.OpenStreamSync(ctx)
	return &stream{str}, err
}

func (c *conn) AcceptStream() (network.MuxedStream, error) {
	str, err := c.wconn.AcceptStream(context.Background())
	return &stream{str}, err
}

func (c *conn) LocalPeer() peer.ID {
	// TODO implement me
	panic("implement me")
}

func (c *conn) LocalPrivateKey() crypto.PrivKey {
	// TODO implement me
	panic("implement me")
}

func (c *conn) RemotePeer() peer.ID {
	// TODO implement me
	panic("implement me")
}

func (c *conn) RemotePublicKey() crypto.PubKey {
	// TODO implement me
	panic("implement me")
}

func (c *conn) LocalMultiaddr() ma.Multiaddr {
	// TODO implement me
	panic("implement me")
}

func (c *conn) RemoteMultiaddr() ma.Multiaddr {
	// TODO implement me
	panic("implement me")
}

func (c *conn) Scope() network.ConnScope {
	// TODO implement me
	panic("implement me")
}

func (c *conn) Transport() tpt.Transport {
	return c.transport
}
