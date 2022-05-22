package libp2pwebtransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
)

type certConfig struct {
	start, end time.Time
	tlsConf    *tls.Config
	sha256     [32]byte // cached from the tlsConf
}

func newCertConfig(start, end time.Time, conf *tls.Config) (*certConfig, error) {
	return &certConfig{
		start:   start,
		end:     end,
		tlsConf: conf,
		sha256:  sha256.Sum256(conf.Certificates[0].Leaf.Raw),
	}, nil
}

// Certificate renewal logic:
// 0. To simplify the math, assume the certificate is valid for 10 days (in real life: 14 days).
// 1. On startup, we generate the first certificate (1).
// 2. After 4 days, we generate a second certificate (2).
//    We don't use that certificate yet, but we advertise the hashes of (1) and (2).
//    That allows clients to connect to us using addresses that are 4 days old.
// 3. After another 4 days, we now actually start using (2).
//    We also generate a third certificate (3), and start advertising the hashes of (2) and (3).
//    We continue to remember the hash of (1) for validation during the Noise handshake for another 4 days,
//    as the client might be connecting with a cached address.
type certManager struct {
	ctx       context.Context
	ctxCancel context.CancelFunc
	refCount  sync.WaitGroup

	certValidity time.Duration // so we can set it in tests

	mx            sync.Mutex
	lastConfig    *certConfig // initially nil
	currentConfig *certConfig
	nextConfig    *certConfig // nil until we have passed half the certValidity of the current config
	addrComp      ma.Multiaddr
}

func newCertManager(certValidity time.Duration) (*certManager, error) {
	m := &certManager{
		certValidity: certValidity,
	}
	m.ctx, m.ctxCancel = context.WithCancel(context.Background())
	if err := m.init(); err != nil {
		return nil, err
	}
	m.refCount.Add(1)
	go func() {
		defer m.refCount.Done()
		if err := m.background(); err != nil {
			log.Fatal(err)
		}
	}()
	return m, nil
}

func (m *certManager) init() error {
	start := time.Now()
	end := start.Add(m.certValidity)
	tlsConf, err := getTLSConf(start, end)
	if err != nil {
		return err
	}
	cc, err := newCertConfig(start, end, tlsConf)
	if err != nil {
		return err
	}
	m.currentConfig = cc
	return m.cacheAddrComponent()
}

func (m *certManager) background() error {
	t := time.NewTicker(m.certValidity * 4 / 9) // make sure we're a bit faster than 1/2
	defer t.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return nil
		case start := <-t.C:
			end := start.Add(m.certValidity)
			tlsConf, err := getTLSConf(start, end)
			if err != nil {
				return err
			}
			cc, err := newCertConfig(start, end, tlsConf)
			if err != nil {
				return err
			}
			m.mx.Lock()
			if m.nextConfig != nil {
				m.lastConfig = m.currentConfig
				m.currentConfig = m.nextConfig
			}
			m.nextConfig = cc
			if err := m.cacheAddrComponent(); err != nil {
				m.mx.Unlock()
				return err
			}
			m.mx.Unlock()
		}
	}
}

func (m *certManager) GetConfig() *tls.Config {
	m.mx.Lock()
	defer m.mx.Unlock()
	return m.currentConfig.tlsConf
}

func (m *certManager) AddrComponent() ma.Multiaddr {
	m.mx.Lock()
	defer m.mx.Unlock()
	return m.addrComp
}

func (m *certManager) Verify(hashes []multihash.DecodedMultihash) error {
	for _, h := range hashes {
		if h.Code != multihash.SHA2_256 {
			return fmt.Errorf("expected SHA256 hash, got %d", h.Code)
		}
		if !bytes.Equal(h.Digest, m.currentConfig.sha256[:]) &&
			(m.nextConfig == nil || !bytes.Equal(h.Digest, m.nextConfig.sha256[:])) &&
			(m.lastConfig == nil || !bytes.Equal(h.Digest, m.lastConfig.sha256[:])) {
			return fmt.Errorf("found unexpected hash: %+x", h.Digest)
		}
	}
	return nil
}

func (m *certManager) cacheAddrComponent() error {
	addr, err := m.addrComponentForCert(m.currentConfig.sha256[:])
	if err != nil {
		return err
	}
	if m.nextConfig != nil {
		comp, err := m.addrComponentForCert(m.nextConfig.sha256[:])
		if err != nil {
			return err
		}
		addr = addr.Encapsulate(comp)
	}
	m.addrComp = addr
	return nil
}

func (m *certManager) addrComponentForCert(hash []byte) (ma.Multiaddr, error) {
	mh, err := multihash.Encode(hash, multihash.SHA2_256)
	if err != nil {
		return nil, err
	}
	certStr, err := multibase.Encode(multibase.Base58BTC, mh)
	if err != nil {
		return nil, err
	}
	return ma.NewComponent(ma.ProtocolWithCode(ma.P_CERTHASH).Name, certStr)
}

func (m *certManager) Close() error {
	m.ctxCancel()
	m.refCount.Wait()
	return nil
}
