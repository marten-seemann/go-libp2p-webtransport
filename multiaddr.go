package libp2pwebtransport

import (
	"errors"
	"net"
	"strconv"

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

func stringToWebtransportMultiaddr(str string) (ma.Multiaddr, error) {
	host, portStr, err := net.SplitHostPort(str)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseInt(portStr, 10, 32)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("failed to parse IP")
	}
	return toWebtransportMultiaddr(&net.UDPAddr{IP: ip, Port: int(port)})
}
