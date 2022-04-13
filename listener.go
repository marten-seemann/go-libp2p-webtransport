package libp2pwebtransport

import (
	"crypto/tls"
	"errors"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"net"
	"net/http"

	tpt "github.com/libp2p/go-libp2p-core/transport"

	"github.com/lucas-clemente/quic-go/http3"
	"github.com/marten-seemann/webtransport-go"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

var errClosed = errors.New("closed")

type listener struct {
	server  webtransport.Server
	tlsConf *tls.Config

	closed       chan struct{} // is closed when Close is called
	serverClosed chan struct{} // is closed when server.Serve returns

	addr      net.Addr
	multiaddr ma.Multiaddr

	queue chan *webtransport.Conn
}

var _ tpt.Listener = &listener{}

func newListener(laddr ma.Multiaddr, tlsConf *tls.Config) (tpt.Listener, error) {
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
		queue:        make(chan *webtransport.Conn, 10),
		serverClosed: make(chan struct{}),
		addr:         udpConn.LocalAddr(),
		tlsConf:      tlsConf,
		multiaddr:    localMultiaddr,
	}
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
	select {
	case <-l.closed:
		return nil, errClosed
	default:
	}

	var c *webtransport.Conn
	select {
	case c = <-l.queue:
		// TODO: libp2p handshake
		// TODO: pass in transport
		return &conn{wconn: c}, nil
	case <-l.closed:
		return nil, errClosed
	}
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
	close(l.closed)
	err := l.server.Close()
	<-l.serverClosed
	return err
}
