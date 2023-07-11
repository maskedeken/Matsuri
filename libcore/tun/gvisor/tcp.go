package gvisor

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"libcore/tun"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/waiter"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
)

func gTcpHandler(s *stack.Stack, handler tun.Handler) {
	forwarder := tcp.NewForwarder(s, 0, 1024, func(request *tcp.ForwarderRequest) {
		id := request.ID()
		waitQueue := new(waiter.Queue)
		endpoint, errT := request.CreateEndpoint(waitQueue)
		if errT != nil {
			newError("failed to create TCP connection").Base(tcpipErr(errT)).WriteToLog()
			// prevent potential half-open TCP connection leak.
			request.Complete(true)
			return
		}
		request.Complete(false)
		srcAddr := net.JoinHostPort(id.RemoteAddress.String(), strconv.Itoa(int(id.RemotePort)))
		src, err := v2rayNet.ParseDestination(fmt.Sprint("tcp:", srcAddr))
		if err != nil {
			newError("[TCP] parse source address ", srcAddr, " failed: ", err).AtWarning().WriteToLog()
			return
		}
		dstAddr := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		dst, err := v2rayNet.ParseDestination(fmt.Sprint("tcp:", dstAddr))
		if err != nil {
			newError("[TCP] parse destination address ", dstAddr, " failed: ", err).AtWarning().WriteToLog()
			return
		}
		go handler.NewConnection(src, dst, gTcpConn{endpoint, gonet.NewTCPConn(waitQueue, endpoint)})
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
}

type gTcpConn struct {
	ep tcpip.Endpoint
	*gonet.TCPConn
}

func (g gTcpConn) Close() error {
	g.ep.Close()
	g.TCPConn.SetDeadline(time.Now().Add(-1))
	return g.TCPConn.Close()
}
