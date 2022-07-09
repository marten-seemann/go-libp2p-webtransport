package libp2pwebtransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"time"

	pb "github.com/marten-seemann/go-libp2p-webtransport/pb"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	tpt "github.com/libp2p/go-libp2p-core/transport"

	noise "github.com/libp2p/go-libp2p-noise"

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

type transport struct {
	privKey ic.PrivKey
	pid     peer.ID

	dialer webtransport.Dialer

	rcmgr network.ResourceManager

	listenOnce    sync.Once
	listenOnceErr error
	certManager   *certManager

	noise *noise.Transport
}

var _ tpt.Transport = &transport{}
var _ io.Closer = &transport{}

func New(key ic.PrivKey, rcmgr network.ResourceManager) (tpt.Transport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	t := &transport{
		pid:     id,
		privKey: key,
		rcmgr:   rcmgr,
		dialer: webtransport.Dialer{
			RoundTripper: &http3.RoundTripper{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // TODO: verify certificate,
			},
		},
	}
	noise, err := noise.New(key, noise.WithEarlyDataHandler(t.checkEarlyData))
	if err != nil {
		return nil, err
	}
	t.noise = noise
	return t, nil
}

func (t *transport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (tpt.CapableConn, error) {
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

	conn, err := t.dial(ctx, raddr, p)
	if err != nil {
		scope.Done()
		return nil, err
	}
	return conn, nil
}

func (t *transport) dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (tpt.CapableConn, error) {
	_, addr, err := manet.DialArgs(raddr)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%s%s", addr, webtransportHTTPEndpoint)
	certHashes, err := extractCertHashes(raddr)
	if err != nil {
		return nil, err
	}
	rsp, wconn, err := t.dialer.Dial(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, fmt.Errorf("invalid response status code: %d", rsp.StatusCode)
	}
	str, err := wconn.OpenStreamSync(ctx)
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
	sconn, err := t.noise.SecureOutboundWithEarlyData(ctx, &webtransportStream{Stream: str, wsess: wconn}, p, msgBytes)
	if err != nil {
		return nil, err
	}
	return newConn(t, wconn, t.privKey, sconn.RemotePublicKey())
}

func (t *transport) checkEarlyData(b []byte) error {
	var msg pb.WebTransport
	if err := msg.Unmarshal(b); err != nil {
		return fmt.Errorf("failed to unmarshal early data protobuf: %w", err)
	}
	hashes := make([]multihash.DecodedMultihash, 0, len(msg.CertHashes))
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
	t.listenOnce.Do(func() {
		t.certManager, t.listenOnceErr = newCertManager(certValidity)
	})
	if t.listenOnceErr != nil {
		return nil, t.listenOnceErr
	}
	return newListener(laddr, t, t.noise, t.certManager, t.rcmgr)
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
