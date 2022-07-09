package libp2pwebtransport

import (
	"errors"
	"net"

	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	manet "github.com/multiformats/go-multiaddr/net"
)

var webtransportMA = ma.StringCast("/quic/webtransport")

var webtransportMatcher = mafmt.And(mafmt.IP, mafmt.Base(ma.P_UDP), mafmt.Base(ma.P_QUIC), mafmt.Base(ma.P_WEBTRANSPORT))

func toWebtransportMultiaddr(na net.Addr) (ma.Multiaddr, error) {
	addr, err := manet.FromNetAddr(na)
	if err != nil {
		return nil, err
	}
	if _, err := addr.ValueForProtocol(ma.P_UDP); err != nil {
		return nil, errors.New("not a UDP address")
	}
	return addr.Encapsulate(webtransportMA), nil
}
