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
	headerCache := buf.New()
	headerCache.Write(ipHdr[:headerLength+header.UDPMinimumSize])

	cache.Advance(int32(headerLength + header.UDPMinimumSize))
	t.handler.HandlePacket(&tun.UDPPacket{
		Src:       source,
		Dst:       destination,
		Data:      cache.Bytes(),
		PutHeader: headerCache.Release,
		WriteBack: func(bytes []byte, addr *net.UDPAddr) (int, error) {
			newHeader := make([]byte, headerCache.Len())
			copy(newHeader, headerCache.Bytes())

			var newSourceAddress tcpip.Address
			var newSourcePort uint16

			if addr != nil {
				newSourceAddress = tcpip.AddrFromSlice(addr.IP)
				newSourcePort = uint16(addr.Port)
			} else {
				newSourceAddress = destinationAddress
				newSourcePort = destinationPort
			}

			newIpHdr := header.IPv4(newHeader)
			newIpHdr.SetSourceAddress(newSourceAddress)
			newIpHdr.SetTotalLength(uint16(int(headerCache.Len()) + len(bytes)))
			newIpHdr.SetChecksum(0)
			newIpHdr.SetChecksum(^newIpHdr.CalculateChecksum())

			udpHdr := header.UDP(headerCache.BytesFrom(headerCache.Len() - header.UDPMinimumSize))
			udpHdr.SetSourcePort(newSourcePort)
			udpHdr.SetLength(uint16(header.UDPMinimumSize + len(bytes)))
			udpHdr.SetChecksum(0)
			udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(bytes, header.PseudoHeaderChecksum(header.UDPProtocolNumber, newSourceAddress, sourceAddress, uint16(header.UDPMinimumSize+len(bytes))))))

			if err := t.writeRawPacket([][]byte{newHeader, bytes}); err != nil {
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
	headerCache := buf.New()
	headerCache.Write(ipHdr[:headerLength+header.UDPMinimumSize])

	cache.Advance(int32(headerLength + header.UDPMinimumSize))
	t.handler.HandlePacket(&tun.UDPPacket{
		Src:       source,
		Dst:       destination,
		Data:      cache.Bytes(),
		PutHeader: headerCache.Release,
		WriteBack: func(bytes []byte, addr *net.UDPAddr) (int, error) {
			newHeader := make([]byte, headerCache.Len())
			copy(newHeader, headerCache.Bytes())

			var newSourceAddress tcpip.Address
			var newSourcePort uint16

			if addr != nil {
				newSourceAddress = tcpip.AddrFromSlice(addr.IP)
				newSourcePort = uint16(addr.Port)
			} else {
				newSourceAddress = destinationAddress
				newSourcePort = destinationPort
			}

			newIpHdr := header.IPv6(newHeader)
			newIpHdr.SetSourceAddress(newSourceAddress)
			newIpHdr.SetPayloadLength(uint16(header.UDPMinimumSize + len(bytes)))

			udpHdr := header.UDP(headerCache.BytesFrom(headerCache.Len() - header.UDPMinimumSize))
			udpHdr.SetSourcePort(newSourcePort)
			udpHdr.SetLength(uint16(header.UDPMinimumSize + len(bytes)))
			udpHdr.SetChecksum(0)
			udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(bytes, header.PseudoHeaderChecksum(header.UDPProtocolNumber, newSourceAddress, sourceAddress, uint16(header.UDPMinimumSize+len(bytes))))))

			if err := t.writeRawPacket([][]byte{headerCache.Bytes(), bytes}); err != nil {
				return 0, newError(err.String())
			}

			return len(bytes), nil
		},
	})
}
