package libp2pwebtransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"sync"

	"github.com/libp2p/go-libp2p-core/peer"
	tpt "github.com/libp2p/go-libp2p-core/transport"

	logging "github.com/ipfs/go-log/v2"
	"github.com/marten-seemann/webtransport-go"
	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	manet "github.com/multiformats/go-multiaddr/net"
)

var log = logging.Logger("webtransport")

const webtransportHTTPEndpoint = "/.well-known/libp2p-webtransport"

type transport struct {
	tlsConf *tls.Config
	dialer  webtransport.Dialer

	initOnce sync.Once
	server   webtransport.Server
}

var _ tpt.Transport = &transport{}

func New() (tpt.Transport, error) {
	tlsConf, err := getTLSConf() // TODO: only do this when initializing a listener
	if err != nil {
		return nil, err
	}
	return &transport{
		tlsConf: tlsConf,
		dialer: webtransport.Dialer{
			TLSClientConf: &tls.Config{InsecureSkipVerify: true}, // TODO: verify certificate,
		},
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
	// TODO: run handshake on conn
	return &conn{
		transport: t,
		wconn:     wconn,
	}, nil
}

var dialMatcher = mafmt.And(mafmt.IP, mafmt.Base(ma.P_UDP), mafmt.Base(ma.P_QUIC), mafmt.Base(ma.P_WEBTRANSPORT))

func (t *transport) CanDial(addr ma.Multiaddr) bool {
	return dialMatcher.Matches(addr)
}

func (t *transport) Listen(laddr ma.Multiaddr) (tpt.Listener, error) {
	return newListener(laddr, t.tlsConf)
}

func (t *transport) Protocols() []int {
	return []int{ma.P_WEBTRANSPORT}
}

func (t *transport) Proxy() bool {
	return false
}
