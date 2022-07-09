package libp2pwebtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/libp2p/go-libp2p-core/network"
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
	rcmgr       network.ResourceManager

	server webtransport.Server

	ctx       context.Context
	ctxCancel context.CancelFunc

	serverClosed chan struct{} // is closed when server.Serve returns

	addr      net.Addr
	multiaddr ma.Multiaddr

	queue chan tpt.CapableConn
}

var _ tpt.Listener = &listener{}

func newListener(laddr ma.Multiaddr, transport tpt.Transport, noise *noise.Transport, certManager *certManager, rcmgr network.ResourceManager) (tpt.Listener, error) {
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
		rcmgr:        rcmgr,
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
	mux.HandleFunc(webtransportHTTPEndpoint, ln.httpHandler)
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

func (l *listener) httpHandler(w http.ResponseWriter, r *http.Request) {
	remoteMultiaddr, err := stringToWebtransportMultiaddr(r.RemoteAddr)
	if err != nil {
		// This should never happen.
		log.Errorw("converting remote address failed", "remote", r.RemoteAddr, "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	connScope, err := l.rcmgr.OpenConnection(network.DirInbound, false, remoteMultiaddr)
	if err != nil {
		log.Debugw("resource manager blocked incoming connection", "addr", r.RemoteAddr, "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// TODO: check ?type=multistream URL param
	c, err := l.server.Upgrade(w, r)
	if err != nil {
		log.Debugw("upgrade failed", "error", err)
		// TODO: think about the status code to use here
		w.WriteHeader(500)
		connScope.Done()
		return
	}
	ctx, cancel := context.WithTimeout(l.ctx, handshakeTimeout)
	conn, err := l.handshake(ctx, c)
	if err != nil {
		cancel()
		log.Debugw("handshake failed", "error", err)
		c.Close()
		connScope.Done()
		return
	}
	cancel()

	if err := connScope.SetPeer(conn.RemotePeer()); err != nil {
		log.Debugw("resource manager blocked incoming connection for peer", "peer", conn.RemotePeer(), "addr", r.RemoteAddr, "error", err)
		conn.Close()
		connScope.Done()
		return
	}

	// TODO: think about what happens when this channel fills up
	l.queue <- conn
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
