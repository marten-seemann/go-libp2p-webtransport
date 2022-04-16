package libp2pwebtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	tpt "github.com/libp2p/go-libp2p-core/transport"

	noise "github.com/libp2p/go-libp2p-noise"

	"github.com/lucas-clemente/quic-go/http3"
	"github.com/marten-seemann/webtransport-go"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
)

var errClosed = errors.New("closed")

const queueLen = 16
const handshakeTimeout = 10 * time.Second

type listener struct {
	transport tpt.Transport
	noise     *noise.Transport

	server  webtransport.Server
	tlsConf *tls.Config

	ctx       context.Context
	ctxCancel context.CancelFunc

	serverClosed chan struct{} // is closed when server.Serve returns

	addr      net.Addr
	multiaddr ma.Multiaddr

	queue chan *webtransport.Conn
}

var _ tpt.Listener = &listener{}

func newListener(laddr ma.Multiaddr, tlsConf *tls.Config, transport tpt.Transport, noise *noise.Transport) (tpt.Listener, error) {
	network, addr, err := manet.DialArgs(laddr)
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, err
	}
	localMultiaddr, err := toWebtransportMultiaddr(udpConn.LocalAddr())
	if err != nil {
		return nil, err
	}
	ln := &listener{
		transport:    transport,
		noise:        noise,
		queue:        make(chan *webtransport.Conn, queueLen),
		serverClosed: make(chan struct{}),
		addr:         udpConn.LocalAddr(),
		tlsConf:      tlsConf,
		multiaddr:    localMultiaddr,
	}
	ln.ctx, ln.ctxCancel = context.WithCancel(context.Background())
	server := webtransport.Server{
		H3: http3.Server{
			Server: &http.Server{
				TLSConfig: tlsConf,
			},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world!"))
	})
	mux.HandleFunc(webtransportHTTPEndpoint, func(w http.ResponseWriter, r *http.Request) {
		// TODO: check ?type=multistream URL param
		c, err := server.Upgrade(w, r)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		// TODO: handle queue overflow
		ln.queue <- c
	})
	server.H3.Handler = mux
	go func() {
		defer close(ln.serverClosed)
		defer func() { udpConn.Close() }()
		if err := server.Serve(udpConn); err != nil {
			// TODO: only output if the server hasn't been closed
			log.Debugw("serving failed", "addr", udpConn.LocalAddr(), "error", err)
		}
	}()
	ln.server = server
	return ln, nil
}

func (l *listener) Accept() (tpt.CapableConn, error) {
	queue := make(chan tpt.CapableConn, queueLen)
	for {
		select {
		case <-l.ctx.Done():
			return nil, errClosed
		default:
		}

		var c *webtransport.Conn
		select {
		case c = <-l.queue:
			go func(c *webtransport.Conn) {
				ctx, cancel := context.WithTimeout(l.ctx, handshakeTimeout)
				defer cancel()
				conn, err := l.handshake(ctx, c)
				if err != nil {
					log.Debugw("handshake failed", "error", err)
					c.Close()
					return
				}
				// TODO: handle queue overflow
				queue <- conn
			}(c)
		case conn := <-queue:
			return conn, nil
		case <-l.ctx.Done():
			return nil, errClosed
		}
	}
}

func (l *listener) handshake(ctx context.Context, c *webtransport.Conn) (tpt.CapableConn, error) {
	str, err := c.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := l.noise.SecureInbound(ctx, &webtransportStream{Stream: str, wconn: c}, "")
	if err != nil {
		return nil, err
	}
	return newConn(l.transport, c, conn.LocalPrivateKey(), conn.RemotePublicKey())
}

func (l *listener) Addr() net.Addr {
	return l.addr
}

func (l *listener) Multiaddr() ma.Multiaddr {
	certHash := certificateHash(l.tlsConf)
	h, err := multihash.Encode(certHash[:], multihash.SHA2_256)
	if err != nil {
		panic(err)
	}
	certHashStr, err := multibase.Encode(multibase.Base58BTC, h)
	if err != nil {
		panic(err)
	}
	return l.multiaddr.Encapsulate(ma.StringCast("/certhash/" + certHashStr))
}

func (l *listener) Close() error {
	l.ctxCancel()
	err := l.server.Close()
	<-l.serverClosed
	return err
}
