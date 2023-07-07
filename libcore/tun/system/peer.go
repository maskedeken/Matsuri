package system

import (
	"github.com/sagernet/gvisor/pkg/tcpip"
)

type peerKey struct {
	destinationAddress tcpip.Address
	sourcePort         uint16
}

type peerValue struct {
	sourceAddress   tcpip.Address
	destinationPort uint16
}
