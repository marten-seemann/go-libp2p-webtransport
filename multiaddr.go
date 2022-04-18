package libp2pwebtransport

import (
	"net"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

var webtransportMA = ma.StringCast("/quic/webtransport")

func toWebtransportMultiaddr(na net.Addr) (ma.Multiaddr, error) {
	udpMA, err := manet.FromNetAddr(na)
	if err != nil {
		return nil, err
	}
	return udpMA.Encapsulate(webtransportMA), nil
}
