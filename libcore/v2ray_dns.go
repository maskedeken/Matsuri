package libcore

import (
	"context"
	"fmt"
	"libcore/doh"
	"libcore/protect"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	dns_feature "github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/features/dns/localdns"
	"github.com/v2fly/v2ray-core/v5/nekoutils"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

// DNS & Protect

var staticHosts = make(map[string][]net.IP)
var tryDomains = make([]string, 0)                                           // server's domain, set when enhanced domain mode
var systemResolver = &net.Resolver{PreferGo: false}                          // Using System API, lookup from current network.
var underlyingResolver = &simpleSekaiWrapper{systemResolver: systemResolver} // Using System API, lookup from non-VPN network.
var v2rayDNSClient unsafe.Pointer
var underlyingDialer = &protect.ProtectedDialer{
	Resolver: func(domain string) ([]net.IP, error) {
		return underlyingResolver.LookupIP("ip", domain)
	},
}
var ipv6Mode int32 // 0:disabled, 1:enabled, 2:prefer, 3:only, -1:ignore

// sekaiResolver
type LocalResolver interface {
	LookupIP(network string, domain string) (string, error)
}

type simpleSekaiWrapper struct {
	systemResolver *net.Resolver
	sekaiResolver  LocalResolver // Android: passed from java (only when VPNService)
}

func (p *simpleSekaiWrapper) LookupIP(network, host string) (ret []net.IP, err error) {
	// NOTE only Android
	isSekai := p.sekaiResolver != nil

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ok := make(chan interface{})
	defer cancel()

	go func() {
		defer func() {
			select {
			case <-ctx.Done():
			default:
				ok <- nil
			}
			close(ok)
		}()

		if isSekai {
			var str string
			str, err = p.sekaiResolver.LookupIP(network, host)
			// java -> go
			if err != nil {
				rcode, err2 := strconv.Atoi(err.Error())
				if err2 == nil {
					err = dns_feature.RCodeError(rcode)
				}
				return
			} else if str == "" {
				err = dns_feature.ErrEmptyResponse
				return
			}
			ret = make([]net.IP, 0)
			for _, ip := range strings.Split(str, ",") {
				ret = append(ret, net.ParseIP(ip))
			}
		} else {
			ret, err = p.systemResolver.LookupIP(context.Background(), network, host)
		}
	}()

	select {
	case <-ctx.Done():
		return nil, newError(fmt.Sprintf("underlyingResolver: context cancelled! (sekai=%t)", isSekai))
	case <-ok:
		return
	}
}

func reorderAddresses(ips []net.IP, preferIPv6 bool) []net.IP {
	var result []net.IP
	for i := 0; i < 2; i++ {
		for _, ip := range ips {
			if (preferIPv6 == (i == 0)) == (ip.To4() == nil) {
				result = append(result, ip)
			}
		}
	}
	return result
}

func setupResolvers() {
	// golang lookup -> System
	net.DefaultResolver = systemResolver

	// dnsClient lookup -> Underlying
	internet.UseAlternativeSystemDNSDialer(underlyingDialer)

	// "localhost" localDns lookup -> Underlying
	localdns.SetLookupFunc(underlyingResolver.LookupIP)

	// doh package
	doh.SetDialContext(underlyingDialer.DialContext)

	// All lookup except dnsClient -> dc.LookupIP()
	// and also set protectedDialer for outbound connections
	internet.UseAlternativeSystemDialer(&protect.ProtectedDialer{
		Resolver: func(domain string) ([]net.IP, error) {
			if ips, ok := staticHosts[domain]; ok && ips != nil {
				return ips, nil
			}

			var ips []net.IP
			if nekoutils.In(tryDomains, domain) {
				switch ipv6Mode {
				case 0: // ipv4 only
					_ips, err := doh.LookupManyDoH(domain, 1)
					if err != nil {
						return nil, err
					}

					ips = _ips.([]net.IP)
				case 3: // ipv6 only
					_ips, err := doh.LookupManyDoH(domain, 28)
					if err != nil {
						return nil, err
					}

					ips = _ips.([]net.IP)
				default:
					_ips4, err := doh.LookupManyDoH(domain, 1)
					if err == nil {
						ips = append(ips, _ips4.([]net.IP)...)
					}

					_ips6, err2 := doh.LookupManyDoH(domain, 28)
					if err2 == nil {
						ips = append(ips, _ips6.([]net.IP)...)
					}

					if err != nil && err2 != nil {
						return nil, err2
					}

					if ipv6Mode != -1 {
						ips = reorderAddresses(ips, ipv6Mode == 2)
					}
				}

				staticHosts[domain] = ips
				return ips, nil
			}

			var err error
			optNetwork := "ip"
			if ipv6Mode == 3 { // ipv6 only
				optNetwork = "ip6"
			} else if ipv6Mode == 0 { // ipv4 only
				optNetwork = "ip4"
			}
			// Have running instance?
			ptr := (*dns_feature.Client)(atomic.LoadPointer(&v2rayDNSClient))
			if ptr != nil && *ptr != nil {
				ips, err = (*ptr).LookupIP(&dns_feature.MatsuriDomainStringEx{
					Domain:     domain,
					OptNetwork: optNetwork,
				})
			} else {
				ips, err = systemResolver.LookupIP(context.Background(), optNetwork, domain)
			}

			if err != nil {
				return nil, err
			}

			switch ipv6Mode {
			case 1, 2:
				ips = reorderAddresses(ips, ipv6Mode == 2)
			default:
			}

			if ipv6Mode > -1 {
				newError("resolved ips: ", ips, " according to the IPv6 policy").AtDebug().WriteToLog()
			}
			return ips, nil
		},
	})

	// UDP ListenPacket
	internet.RegisterListenerController(func(network, address string, fd uintptr) error {
		if protect.FdProtector != nil {
			protect.FdProtector.Protect(int32(fd))
		}
		return nil
	})
}
