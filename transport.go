package libp2pwebtransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	tpt "github.com/libp2p/go-libp2p-core/transport"
	noise "github.com/libp2p/go-libp2p-noise"

	logging "github.com/ipfs/go-log/v2"
	"github.com/marten-seemann/webtransport-go"
	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
)

var log = logging.Logger("webtransport")

const webtransportHTTPEndpoint = "/.well-known/libp2p-webtransport"

const maxProtoSize = 8 << 10

const certValidity = 14 * 24 * time.Hour

type transport struct {
	privKey ic.PrivKey
	pid     peer.ID

	tlsConf *tls.Config
	dialer  webtransport.Dialer

	initOnce sync.Once
	server   webtransport.Server

	noise *noise.Transport
}

var _ tpt.Transport = &transport{}

func New(key ic.PrivKey) (tpt.Transport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tlsConf, err := getTLSConf(now, now.Add(certValidity)) // TODO: only do this when initializing a listener
	if err != nil {
		return nil, err
	}
	noise, err := noise.New(key)
	if err != nil {
		return nil, err
	}
	return &transport{
		pid:     id,
		privKey: key,
		tlsConf: tlsConf,
		dialer: webtransport.Dialer{
			TLSClientConf: &tls.Config{InsecureSkipVerify: true}, // TODO: verify certificate,
		},
		noise: noise,
	}, nil
}

func (t *transport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (tpt.CapableConn, error) {
	_, addr, err := manet.DialArgs(raddr)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%s%s", addr, webtransportHTTPEndpoint)
	certHashesStr := make([]string, 0, 2)
	ma.ForEach(raddr, func(c ma.Component) bool {
		if c.Protocol().Code == ma.P_CERTHASH {
			certHashesStr = append(certHashesStr, c.Value())
		}
		return true
	})
	var certHashes []multihash.DecodedMultihash
	for _, s := range certHashesStr {
		_, ch, err := multibase.Decode(s)
		if err != nil {
			return nil, fmt.Errorf("failed to multibase-decode certificate hash: %w", err)
		}
		dh, err := multihash.Decode(ch)
		if err != nil {
			return nil, fmt.Errorf("failed to multihash-decode certificate hash: %w", err)
		}
		certHashes = append(certHashes, *dh)
	}
	rsp, wconn, err := t.dialer.Dial(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, fmt.Errorf("invalid response status code: %d", rsp.StatusCode)
	}
	str, err := wconn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	// TODO: use early data and verify the cert hash
	sconn, err := t.noise.SecureOutbound(ctx, &webtransportStream{Stream: str, wconn: wconn}, p)
	if err != nil {
		return nil, err
	}
	return newConn(t, wconn, t.privKey, sconn.RemotePublicKey())
}

var dialMatcher = mafmt.And(mafmt.IP, mafmt.Base(ma.P_UDP), mafmt.Base(ma.P_QUIC), mafmt.Base(ma.P_WEBTRANSPORT))

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
	return dialMatcher.Matches(addr)
}

func (t *transport) Listen(laddr ma.Multiaddr) (tpt.Listener, error) {
	return newListener(laddr, t.tlsConf, t, t.noise)
}

func (t *transport) Protocols() []int {
	return []int{ma.P_WEBTRANSPORT}
}

func (t *transport) Proxy() bool {
	return false
}
