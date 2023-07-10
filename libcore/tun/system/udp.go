package system

import (
	"libcore/tun"
	"net"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/v2fly/v2ray-core/v5/common/buf"
)

func (t *SystemTun) processIPv4UDP(cache *buf.Buffer, ipHdr header.IPv4, hdr header.UDP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := hdr.SourcePort()
	destinationPort := hdr.DestinationPort()

	source := &net.UDPAddr{
		IP:   sourceAddress.AsSlice(),
		Port: int(sourcePort),
	}
	destination := &net.UDPAddr{
		IP:   destinationAddress.AsSlice(),
		Port: int(destinationPort),
	}

	ipHdr.SetDestinationAddress(sourceAddress)
	hdr.SetDestinationPort(sourcePort)

	headerLength := ipHdr.HeaderLength()
	headerCache := make([]byte, headerLength+header.UDPMinimumSize)
	copy(headerCache, ipHdr[:headerLength+header.UDPMinimumSize])

	cache.Advance(int32(headerLength + header.UDPMinimumSize))
	t.handler.HandlePacket(&tun.UDPPacket{
		Src:  source,
		Dst:  destination,
		Data: cache.Bytes(),
		WriteBack: func(bytes []byte, addr *net.UDPAddr) (int, error) {
			reply := buf.New()
			defer reply.Release()

			reply.Write(headerCache)
			reply.Write(bytes)

			var newSourceAddress tcpip.Address
			var newSourcePort uint16

			if addr != nil {
				newSourceAddress = tcpip.AddrFromSlice(addr.IP)
				newSourcePort = uint16(addr.Port)
			} else {
				newSourceAddress = destinationAddress
				newSourcePort = destinationPort
			}

			newIpHdr := header.IPv4(reply.Bytes())
			newIpHdr.SetSourceAddress(newSourceAddress)
			newIpHdr.SetTotalLength(uint16(len(headerCache) + len(bytes)))
			newIpHdr.SetChecksum(0)
			newIpHdr.SetChecksum(^newIpHdr.CalculateChecksum())

			udpHdr := header.UDP(reply.BytesFrom(int32(headerLength)))
			udpHdr.SetSourcePort(newSourcePort)
			udpHdr.SetLength(uint16(header.UDPMinimumSize + len(bytes)))
			udpHdr.SetChecksum(0)
			udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(bytes, header.PseudoHeaderChecksum(header.UDPProtocolNumber, newSourceAddress, sourceAddress, uint16(header.UDPMinimumSize+len(bytes))))))

			if err := t.writeBuffer(reply.Bytes()); err != nil {
				return 0, newError(err.String())
			}

			return len(bytes), nil
		},
	})
}

func (t *SystemTun) processIPv6UDP(cache *buf.Buffer, ipHdr header.IPv6, hdr header.UDP) {
	sourceAddress := ipHdr.SourceAddress()
	destinationAddress := ipHdr.DestinationAddress()
	sourcePort := hdr.SourcePort()
	destinationPort := hdr.DestinationPort()

	source := &net.UDPAddr{
		IP:   sourceAddress.AsSlice(),
		Port: int(sourcePort),
	}
	destination := &net.UDPAddr{
		IP:   destinationAddress.AsSlice(),
		Port: int(destinationPort),
	}

	ipHdr.SetDestinationAddress(sourceAddress)
	hdr.SetDestinationPort(sourcePort)

	headerLength := uint16(len(ipHdr)) - ipHdr.PayloadLength()
	headerCache := make([]byte, headerLength+header.UDPMinimumSize)
	copy(headerCache, ipHdr[:headerLength+header.UDPMinimumSize])

	cache.Advance(int32(headerLength + header.UDPMinimumSize))
	t.handler.HandlePacket(&tun.UDPPacket{
		Src:  source,
		Dst:  destination,
		Data: cache.Bytes(),
		WriteBack: func(bytes []byte, addr *net.UDPAddr) (int, error) {
			reply := buf.New()
			defer reply.Release()

			reply.Write(headerCache)
			reply.Write(bytes)

			var newSourceAddress tcpip.Address
			var newSourcePort uint16

			if addr != nil {
				newSourceAddress = tcpip.AddrFromSlice(addr.IP)
				newSourcePort = uint16(addr.Port)
			} else {
				newSourceAddress = destinationAddress
				newSourcePort = destinationPort
			}

			newIpHdr := header.IPv6(reply.Bytes())
			newIpHdr.SetSourceAddress(newSourceAddress)
			newIpHdr.SetPayloadLength(uint16(header.UDPMinimumSize + len(bytes)))

			udpHdr := header.UDP(reply.BytesFrom(int32(headerLength)))
			udpHdr.SetSourcePort(newSourcePort)
			udpHdr.SetLength(uint16(header.UDPMinimumSize + len(bytes)))
			udpHdr.SetChecksum(0)
			udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(bytes, header.PseudoHeaderChecksum(header.UDPProtocolNumber, newSourceAddress, sourceAddress, uint16(header.UDPMinimumSize+len(bytes))))))

			if err := t.writeBuffer(reply.Bytes()); err != nil {
				return 0, newError(err.String())
			}

			return len(bytes), nil
		},
	})
}
