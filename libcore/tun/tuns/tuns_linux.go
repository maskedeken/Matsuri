package tuns

import (
	"libcore/tun"
	"libcore/tun/gvisor"
	"libcore/tun/system"
	"libcore/tun/tun2socket"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"
)

func NewGvisor(dev int32, mtu int32, handler tun.Handler, nicId int32, ipv6Mode int32) (tun.Tun, error) {
	endpoint, err := fdbased.New(&fdbased.Options{
		FDs: []int{int(dev)},
		MTU: uint32(mtu),
	})
	if err != nil {
		return nil, err
	}

	return gvisor.New(endpoint, handler, tcpip.NICID(nicId), ipv6Mode)
}

func NewSystem(dev int32, mtu int32, handler tun.Handler, ipv6Mode int32, errorHandler func(err string)) (tun.Tun, error) {
	return system.New(dev, mtu, handler, ipv6Mode, errorHandler)
}

func NewTun2Socket(fd int32, handler tun.Handler) (tun.Tun, error) {
	return tun2socket.New(fd, handler)
}
