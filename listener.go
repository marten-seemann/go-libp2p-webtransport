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
)

var errClosed = errors.New("closed")

const queueLen = 16
const handshakeTimeout = 10 * time.Second

type listener struct {
	transport   tpt.Transport
	noise       *noise.Transport
	certManager *certManager

	server webtransport.Server

	ctx       context.Context
	ctxCancel context.CancelFunc

	serverClosed chan struct{} // is closed when server.Serve returns

	addr      net.Addr
	multiaddr ma.Multiaddr

	queue chan tpt.CapableConn
}

var _ tpt.Listener = &listener{}

func newListener(laddr ma.Multiaddr, transport tpt.Transport, noise *noise.Transport, certManager *certManager) (tpt.Listener, error) {
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
		certManager:  certManager,
		queue:        make(chan tpt.CapableConn, queueLen),
		serverClosed: make(chan struct{}),
		addr:         udpConn.LocalAddr(),
		multiaddr:    localMultiaddr,
		server: webtransport.Server{
			H3: http3.Server{
				TLSConfig: &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return certManager.GetConfig(), nil
				}},
			},
		},
	}
	ln.ctx, ln.ctxCancel = context.WithCancel(context.Background())
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world!"))
	})
	mux.HandleFunc(webtransportHTTPEndpoint, func(w http.ResponseWriter, r *http.Request) {
		// TODO: check ?type=multistream URL param
		c, err := ln.server.Upgrade(w, r)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		ctx, cancel := context.WithTimeout(ln.ctx, handshakeTimeout)
		conn, err := ln.handshake(ctx, c)
		if err != nil {
			cancel()
			log.Debugw("handshake failed", "error", err)
			c.Close()
			return
		}
		cancel()
		ln.queue <- conn
		// We need to block until we're done with this WebTransport session.
		<-c.Context().Done()
	})
	ln.server.H3.Handler = mux
	go func() {
		defer close(ln.serverClosed)
		defer func() { udpConn.Close() }()
		if err := ln.server.Serve(udpConn); err != nil {
			// TODO: only output if the server hasn't been closed
			log.Debugw("serving failed", "addr", udpConn.LocalAddr(), "error", err)
		}
	}()
	return ln, nil
}

func (l *listener) Accept() (tpt.CapableConn, error) {
	select {
	case <-l.ctx.Done():
		return nil, errClosed
	case c := <-l.queue:
		return c, nil
	}
}

func (l *listener) handshake(ctx context.Context, sess *webtransport.Session) (tpt.CapableConn, error) {
	str, err := sess.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := l.noise.SecureInbound(ctx, &webtransportStream{Stream: str, wsess: sess}, "")
	if err != nil {
		return nil, err
	}
	return newConn(l.transport, sess, conn.LocalPrivateKey(), conn.RemotePublicKey())
}

func (l *listener) Addr() net.Addr {
	return l.addr
}

func (l *listener) Multiaddr() ma.Multiaddr {
	return l.multiaddr.Encapsulate(l.certManager.AddrComponent())
}

func (l *listener) Close() error {
	l.ctxCancel()
	err := l.server.Close()
	<-l.serverClosed
	return err
}
