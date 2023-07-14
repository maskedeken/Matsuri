package gvisor

import (
	"errors"

	"libcore/comm"
	"libcore/tun"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sirupsen/logrus"
	"github.com/v2fly/v2ray-core/v5/common/buf"
)

//go:generate go run ../errorgen

var _ tun.Tun = (*GVisor)(nil)

type GVisor struct {
	Endpoint stack.LinkEndpoint
	Stack    *stack.Stack
}

func (t *GVisor) Stop() {
	t.Stack.Close()
}

const DefaultNIC tcpip.NICID = 0x01

func New(endpoint stack.LinkEndpoint, handler tun.Handler, nicId tcpip.NICID, ipv6Mode int32) (*GVisor, error) {
	// endpoint, _ := newRwEndpoint(dev, mtu)
	var o stack.Options
	switch ipv6Mode {
	case comm.IPv6Disable:
		o = stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol4,
			},
		}
	case comm.IPv6Only:
		o = stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol6,
			},
		}
	default:
		o = stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
				icmp.NewProtocol4,
				icmp.NewProtocol6,
			},
		}
	}
	s := stack.New(o)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicId,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicId,
		},
	})

	bufSize := buf.Size
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})

	sOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)

	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)

	gTcpHandler(s, handler)
	gUdpHandler(s, handler)
	gMust(s.CreateNIC(nicId, endpoint))
	gMust(s.SetSpoofing(nicId, true))
	gMust(s.SetPromiscuousMode(nicId, true))

	return &GVisor{endpoint, s}, nil
}

func gMust(err tcpip.Error) {
	if err != nil {
		logrus.Panicln(err.String())
	}
}

func tcpipErr(err tcpip.Error) error {
	return errors.New(err.String())
}
