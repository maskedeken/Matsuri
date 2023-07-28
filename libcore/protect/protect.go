package protect

import (
	"context"
	"net"
	"runtime"
	_ "unsafe"

	"github.com/sirupsen/logrus"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	v2rayNet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

//go:linkname effectiveSystemDialer_ github.com/v2fly/v2ray-core/v5/transport/internet.effectiveSystemDialer
var effectiveSystemDialer_ internet.SystemDialer

var v2rayDefaultDialer *internet.DefaultSystemDialer

func init() {
	var ok bool
	v2rayDefaultDialer, ok = effectiveSystemDialer_.(*internet.DefaultSystemDialer)
	if !ok {
		panic("v2rayDefaultDialer not found")
	}
}

// non-Windows
// May be a func to apply fwmark to the fd (implement by Android or Nekoray)
type Protector interface {
	Protect(fd int32) bool
}

var FdProtector Protector

// Use my dial function on non-Windows platforms
// Use v2ray's dial on Windows
type ProtectedDialer struct {
	Resolver func(domain string) ([]net.IP, error)
}

func (dialer ProtectedDialer) Dial(ctx context.Context, source v2rayNet.Address, destination v2rayNet.Destination, sockopt *internet.SocketConfig) (conn net.Conn, err error) {
	if destination.Network == v2rayNet.Network_Unknown || destination.Address == nil {
		buffer := buf.StackNew()
		buffer.Resize(0, int32(runtime.Stack(buffer.Extend(buf.Size), false)))
		logrus.Warn("connect to invalid destination:\n", buffer.String())
		buffer.Release()

		return nil, newError("invalid destination")
	}

	if destination.Address.Family().IsIP() {
		ip := destination.Address.IP()
		if ip.IsLoopback() { // is it more effective
			return v2rayDefaultDialer.Dial(ctx, source, destination, sockopt)
		}
		return dialer.dial(ctx, source, destination, sockopt)
	}

	if dialer.Resolver == nil {
		return nil, newError("no resolver")
	}

	ob := session.OutboundFromContext(ctx)
	if ob == nil {
		return nil, newError("outbound is not specified")
	}

	r := ob.Resolved
	if r == nil {
		var ips []net.IP
		ips, err = dialer.Resolver(destination.Address.Domain())
		if err != nil {
			return nil, err
		}

		r = &session.Resolved{
			IPs: ips,
		}
		ob.Resolved = r
	}

	ip := r.CurrentIP()
	if ip == nil {
		return nil, newError("no IP specified")
	}

	destination.Address = v2rayNet.IPAddress(ip)
	conn, err = dialer.dial(ctx, source, destination, sockopt)
	if err != nil {
		r.NextIP()
		return nil, err
	}

	return
}
