package libp2pwebtransport

import (
	"context"
	"github.com/libp2p/go-libp2p-core/network"
	tpt "github.com/libp2p/go-libp2p-core/transport"

	"github.com/marten-seemann/webtransport-go"
)

type conn struct {
	connSecurityMultiaddrs

	transport tpt.Transport
	session   *webtransport.Session

	scope network.ConnScope
}

var _ tpt.CapableConn = &conn{}

func newConn(tr tpt.Transport, sess *webtransport.Session, sconn connSecurityMultiaddrs, scope network.ConnScope) *conn {
	return &conn{
		connSecurityMultiaddrs: sconn,
		transport:              tr,
		session:                sess,
		scope:                  scope,
	}
}

func (c *conn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	str, err := c.session.OpenStreamSync(ctx)
	return &stream{str}, err
}

func (c *conn) AcceptStream() (network.MuxedStream, error) {
	str, err := c.session.AcceptStream(context.Background())
	return &stream{str}, err
}

func (c *conn) Close() error             { return c.session.Close() }
func (c *conn) IsClosed() bool           { return c.session.Context().Err() != nil }
func (c *conn) Scope() network.ConnScope { return c.scope }
func (c *conn) Transport() tpt.Transport { return c.transport }
