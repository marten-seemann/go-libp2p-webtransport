package libp2pwebtransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	pb "github.com/marten-seemann/go-libp2p-webtransport/pb"

	"github.com/libp2p/go-libp2p-core/connmgr"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	tpt "github.com/libp2p/go-libp2p-core/transport"

	noise "github.com/libp2p/go-libp2p-noise"

	"github.com/benbjohnson/clock"
	logging "github.com/ipfs/go-log/v2"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/marten-seemann/webtransport-go"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/multiformats/go-multihash"
)

var log = logging.Logger("webtransport")

const webtransportHTTPEndpoint = "/.well-known/libp2p-webtransport"

const certValidity = 14 * 24 * time.Hour

type Option func(*transport) error

func WithClock(cl clock.Clock) Option {
	return func(t *transport) error {
		t.clock = cl
		return nil
	}
}

// WithTLSConfig sets a tls.Config used for listening.
// When used, the certificate from that config will be used, and no /certhash will be added to the listener's multiaddr.
// This is most useful when running a listener that has a valid (CA-signed) certificate.
func WithTLSConfig(c *tls.Config) Option {
	return func(t *transport) error {
		t.staticTLSConf = c
		return nil
	}
}

// WithTLSClientConfig sets a custom tls.Config used for dialing.
// This option is most useful for setting a custom tls.Config.RootCAs certificate pool.
// When dialing a multiaddr that contains a /certhash component, this library will set InsecureSkipVerify and
// overwrite the VerifyPeerCertificate callback.
func WithTLSClientConfig(c *tls.Config) Option {
	return func(t *transport) error {
		t.tlsClientConf = c
		return nil
	}
}

type transport struct {
	privKey ic.PrivKey
	pid     peer.ID
	clock   clock.Clock

	rcmgr network.ResourceManager
	gater connmgr.ConnectionGater

	listenOnce    sync.Once
	listenOnceErr error
	certManager   *certManager
	staticTLSConf *tls.Config
	tlsClientConf *tls.Config

	noise *noise.Transport
}

var _ tpt.Transport = &transport{}
var _ io.Closer = &transport{}

func New(key ic.PrivKey, gater connmgr.ConnectionGater, rcmgr network.ResourceManager, opts ...Option) (tpt.Transport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	t := &transport{
		pid:     id,
		privKey: key,
		rcmgr:   rcmgr,
		gater:   gater,
		clock:   clock.New(),
	}
	for _, opt := range opts {
		if err := opt(t); err != nil {
			return nil, err
		}
	}
	noise, err := noise.New(key, noise.WithEarlyDataHandler(t.checkEarlyData))
	if err != nil {
		return nil, err
	}
	t.noise = noise
	return t, nil
}

func (t *transport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (tpt.CapableConn, error) {
	_, addr, err := manet.DialArgs(raddr)
	if err != nil {
		return nil, err
	}
	certHashes, err := extractCertHashes(raddr)
	if err != nil {
		return nil, err
	}

	scope, err := t.rcmgr.OpenConnection(network.DirOutbound, false, raddr)
	if err != nil {
		log.Debugw("resource manager blocked outgoing connection", "peer", p, "addr", raddr, "error", err)
		return nil, err
	}
	if err := scope.SetPeer(p); err != nil {
		log.Debugw("resource manager blocked outgoing connection for peer", "peer", p, "addr", raddr, "error", err)
		scope.Done()
		return nil, err
	}

	sess, err := t.dial(ctx, addr, certHashes)
	if err != nil {
		scope.Done()
		return nil, err
	}
	sconn, err := t.upgrade(ctx, sess, p, certHashes)
	if err != nil {
		sess.Close()
		scope.Done()
		return nil, err
	}
	if t.gater != nil && !t.gater.InterceptSecured(network.DirOutbound, p, sconn) {
		// TODO: can we close with a specific error here?
		sess.Close()
		return nil, fmt.Errorf("secured connection gated")
	}

	return newConn(t, sess, sconn, scope), nil
}

func (t *transport) dial(ctx context.Context, addr string, certHashes []multihash.DecodedMultihash) (*webtransport.Session, error) {
	url := fmt.Sprintf("https://%s%s", addr, webtransportHTTPEndpoint)
	var tlsConf *tls.Config
	if t.tlsClientConf != nil {
		tlsConf = t.tlsClientConf.Clone()
	} else {
		tlsConf = &tls.Config{}
	}

	if len(certHashes) > 0 {
		tlsConf.InsecureSkipVerify = true // this is not insecure. We verify the certificate ourselves.
		tlsConf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyRawCerts(rawCerts, certHashes)
		}
	}
	dialer := webtransport.Dialer{
		RoundTripper: &http3.RoundTripper{TLSClientConfig: tlsConf},
	}
	rsp, sess, err := dialer.Dial(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, fmt.Errorf("invalid response status code: %d", rsp.StatusCode)
	}
	return sess, err
}

func (t *transport) upgrade(ctx context.Context, sess *webtransport.Session, p peer.ID, certHashes []multihash.DecodedMultihash) (connSecurityMultiaddrs, error) {
	local, err := toWebtransportMultiaddr(sess.LocalAddr())
	if err != nil {
		return nil, fmt.Errorf("error determiniting local addr: %w", err)
	}
	remote, err := toWebtransportMultiaddr(sess.RemoteAddr())
	if err != nil {
		return nil, fmt.Errorf("error determiniting remote addr: %w", err)
	}

	str, err := sess.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	// Now run a Noise handshake (using early data) and verify the cert hash.
	msg := pb.WebTransport{CertHashes: make([][]byte, 0, len(certHashes))}
	for _, certHash := range certHashes {
		h, err := multihash.Encode(certHash.Digest, certHash.Code)
		if err != nil {
			return nil, fmt.Errorf("failed to encode certificate hash: %w", err)
		}
		msg.CertHashes = append(msg.CertHashes, h)
	}
	msgBytes, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal WebTransport protobuf: %w", err)
	}
	c, err := t.noise.SecureOutboundWithEarlyData(ctx, &webtransportStream{Stream: str, wsess: sess}, p, msgBytes)
	if err != nil {
		return nil, err
	}
	return &connSecurityMultiaddrsImpl{
		ConnSecurity:   c,
		ConnMultiaddrs: &connMultiaddrs{local: local, remote: remote},
	}, nil
}

func (t *transport) checkEarlyData(b []byte) error {
	var msg pb.WebTransport
	if err := msg.Unmarshal(b); err != nil {
		return fmt.Errorf("failed to unmarshal early data protobuf: %w", err)
	}
	hashes := make([]multihash.DecodedMultihash, 0, len(msg.CertHashes))

	if t.staticTLSConf != nil {
		if len(hashes) > 0 {
			return errors.New("using static TLS config, didn't expect any certificate hashes")
		}
		return nil
	}

	for _, h := range msg.CertHashes {
		dh, err := multihash.Decode(h)
		if err != nil {
			return fmt.Errorf("failed to decode hash: %w", err)
		}
		hashes = append(hashes, *dh)
	}
	return t.certManager.Verify(hashes)
}

func (t *transport) CanDial(addr ma.Multiaddr) bool {
	var numHashes int
	ma.ForEach(addr, func(c ma.Component) bool {
		if c.Protocol().Code == ma.P_CERTHASH {
			numHashes++
		}
		return true
	})
	if numHashes == 0 {
		return false
	}
	for i := 0; i < numHashes; i++ {
		addr, _ = ma.SplitLast(addr)
	}
	return webtransportMatcher.Matches(addr)
}

func (t *transport) Listen(laddr ma.Multiaddr) (tpt.Listener, error) {
	if !webtransportMatcher.Matches(laddr) {
		return nil, fmt.Errorf("cannot listen on non-WebTransport addr: %s", laddr)
	}
	if t.staticTLSConf == nil {
		t.listenOnce.Do(func() {
			t.certManager, t.listenOnceErr = newCertManager(t.clock)
		})
		if t.listenOnceErr != nil {
			return nil, t.listenOnceErr
		}
	}
	return newListener(laddr, t, t.noise, t.certManager, t.staticTLSConf, t.gater, t.rcmgr)
}

func (t *transport) Protocols() []int {
	return []int{ma.P_WEBTRANSPORT}
}

func (t *transport) Proxy() bool {
	return false
}

func (t *transport) Close() error {
	t.listenOnce.Do(func() {})
	if t.certManager != nil {
		return t.certManager.Close()
	}
	return nil
}
