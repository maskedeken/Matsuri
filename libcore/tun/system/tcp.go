package system

import (
	"context"
	"errors"
	"net"

	"libcore/comm"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sirupsen/logrus"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
)

type peerConn struct {
	net.Conn
	destinationAddress tcpip.Address
	sourcePort         uint16
	sessionCache       *cache.LruCache
}

func (c *peerConn) Close() error {
	c.sessionCache.Delete(peerKey{c.destinationAddress, c.sourcePort})
	return c.Conn.Close()
}

type tcpForwarder struct {
	tun      *SystemTun
	port     uint16
	listener *net.TCPListener
	sessions *cache.LruCache

	ctx    context.Context
	cancel context.CancelFunc
}

func newTcpForwarder(tun *SystemTun) (*tcpForwarder, error) {
	var network string
	address := &net.TCPAddr{}
	if tun.ipv6Mode == comm.IPv6Disable {
		network = "tcp4"
		address.IP = net.IP(vlanClient4.AsSlice())
	} else {
		network = "tcp"
		address.IP = net.IPv6zero
	}
	listener, err := net.ListenTCP(network, address)
	if err != nil {
		return nil, newError("failed to create tcp forwarder at ", address.IP).Base(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	port := uint16(addr.Port)
	newError("tcp forwarder started at ", addr).AtDebug().WriteToLog()
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	return &tcpForwarder{tun, port, listener, cache.New(
		cache.WithAge(300),
		cache.WithUpdateAgeOnGet(),
	), ctx, cancel}, nil
}

func (t *tcpForwarder) dispatch() (bool, error) {
	conn, err := t.listener.AcceptTCP()
	if err != nil {
		return true, err
	}
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if ip4 := addr.IP.To4(); ip4 != nil {
		addr.IP = ip4
	}
	key := peerKey{tcpip.AddrFromSlice(addr.IP), uint16(addr.Port)}
	var session *peerValue
	iSession, ok := t.sessions.Get(key)
	if ok {
		session = iSession.(*peerValue)
	} else {
		conn.Close()
		return false, newError("dropped unknown tcp session with source port ", key.sourcePort, " to destination address ", key.destinationAddress)
	}

	source := v2rayNet.Destination{
		Address: v2rayNet.IPAddress([]byte(session.sourceAddress.AsSlice())),
		Port:    v2rayNet.Port(key.sourcePort),
		Network: v2rayNet.Network_TCP,
	}
	destination := v2rayNet.Destination{
		Address: v2rayNet.IPAddress([]byte(key.destinationAddress.AsSlice())),
		Port:    v2rayNet.Port(session.destinationPort),
		Network: v2rayNet.Network_TCP,
	}

	pc := &peerConn{
		Conn:               conn,
		destinationAddress: key.destinationAddress,
		sourcePort:         key.sourcePort,
		sessionCache:       t.sessions,
	}
	go t.tun.handler.NewConnection(source, destination, pc)
	return false, nil
}

func (t *tcpForwarder) dispatchLoop() {
	for {
		stop, err := t.dispatch()
		if err != nil {
			e := newError("dispatch tcp conn failed").Base(err)
			e.WriteToLog()
			if stop {
				if !errors.Is(err, net.ErrClosed) {
					t.Close()
					t.tun.errorHandler(e.String())
				}
				return
			}
		}
	}
}

func (t *tcpForwarder) processIPv4(ipHdr header.IPv4, tcpHdr header.TCP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := tcpHdr.SourcePort()
	destinationPort := tcpHdr.DestinationPort()

	if sourcePort != t.port {

		key := peerKey{destinationAddress, sourcePort}
		if _, ok := t.sessions.Get(key); !ok {
			t.sessions.Set(key, &peerValue{sourceAddress, destinationPort})
		}

		ipHdr.SetSourceAddress(destinationAddress)
		ipHdr.SetDestinationAddress(vlanClient4)
		tcpHdr.SetDestinationPort(t.port)

	} else {

		var session *peerValue
		iSession, ok := t.sessions.Get(peerKey{destinationAddress, destinationPort})
		if ok {
			session = iSession.(*peerValue)
		} else {
			logrus.Warn("unknown tcp session with source port ", destinationPort, " to destination address ", destinationAddress)
			return
		}
		ipHdr.SetSourceAddress(destinationAddress)
		tcpHdr.SetSourcePort(session.destinationPort)
		ipHdr.SetDestinationAddress(session.sourceAddress)
	}

	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), uint16(len(tcpHdr))),
		checksum.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) processIPv6(ipHdr header.IPv6, tcpHdr header.TCP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := tcpHdr.SourcePort()
	destinationPort := tcpHdr.DestinationPort()

	if sourcePort != t.port {

		key := peerKey{destinationAddress, sourcePort}
		if _, ok := t.sessions.Get(key); !ok {
			t.sessions.Set(key, &peerValue{sourceAddress, destinationPort})
		}

		ipHdr.SetSourceAddress(destinationAddress)
		ipHdr.SetDestinationAddress(vlanClient6)
		tcpHdr.SetDestinationPort(t.port)

	} else {

		var session *peerValue
		iSession, ok := t.sessions.Get(peerKey{destinationAddress, destinationPort})
		if ok {
			session = iSession.(*peerValue)
		} else {
			logrus.Warn("unknown tcp session with source port ", destinationPort, " to destination address ", destinationAddress)
			return
		}

		ipHdr.SetSourceAddress(destinationAddress)
		tcpHdr.SetSourcePort(session.destinationPort)
		ipHdr.SetDestinationAddress(session.sourceAddress)
	}

	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress(), uint16(len(tcpHdr))),
		checksum.Checksum(tcpHdr.Payload(), 0),
	)))

	t.tun.writeBuffer(ipHdr)
}

func (t *tcpForwarder) Close() error {
	t.cancel()
	return t.listener.Close()
}
