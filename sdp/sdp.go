package sdp

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	Chacha20poly1305 = 0
	GM               = 1
)

type SDP struct {
	CipherAlgorithm int
	PacketLogEnable bool
	IsServer        bool
	RekeyTimeout    int
	//Info            Info
}

type FiveTuple struct {
	SrcIP    net.IP
	DstIP    net.IP
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
}

func ParseFiveTuple(packet []byte) (*FiveTuple, []byte) {
	packetLen := len(packet)
	var protocol uint8
	var srcIP net.IP
	var dstIP net.IP
	var transportOffset int
	switch packet[0] >> 4 {
	case 4:
		flagsfrags := binary.BigEndian.Uint16(packet[6:8])
		//flags := flagsfrags >> 13
		//mf := flags & 0x01
		fragOffset := flagsfrags & 0x1FFF
		if fragOffset != 0 {
			return nil, nil
		}
		protocol = packet[9]
		srcIP = packet[12:16]
		dstIP = packet[16:20]
		headerLen := packet[0] & 0x0f
		transportOffset = 4 * int(headerLen)
	case 6:
		protocol = packet[6]
		transportOffset = 40
		if protocol == 44 {
			protocol = packet[transportOffset]
			//mf := packet[transportOffset+3] & 0x1
			fragOffset := binary.BigEndian.Uint16(packet[transportOffset+2:transportOffset+4]) >> 3
			// fragment header 8
			transportOffset += 8
			if fragOffset != 0 {
				return nil, nil
			}
		}
		srcIP = packet[8:24]
		dstIP = packet[24:40]
	default:
		return nil, nil
	}
	var payloadOffset int
	if protocol == 17 {
		// UDP
		if len(packet)-transportOffset < 8 {
			return nil, nil
		}
		// udp header 8
		payloadOffset = transportOffset + 8
	} else if protocol == 6 {
		// TCP
		if packetLen-transportOffset < 20 {
			return nil, nil
		}
		tcpHeaderLen := packet[transportOffset+12] >> 4
		if tcpHeaderLen < 5 || packetLen-transportOffset < 4*int(tcpHeaderLen) {
			return nil, nil
		}
		payloadOffset = transportOffset + 4*int(tcpHeaderLen)
	} else {
		return &FiveTuple{srcIP, dstIP, protocol, 0, 0}, nil
	}
	port := packet[transportOffset : transportOffset+2]
	srcPort := binary.BigEndian.Uint16(port)
	portOffset := transportOffset + 2
	port = packet[portOffset : portOffset+2]
	dstPort := binary.BigEndian.Uint16(port)

	return &FiveTuple{srcIP, dstIP, protocol, srcPort, dstPort}, packet[payloadOffset:]
}

func (f *FiveTuple) String() string {
	protocol := fmt.Sprintf("%d", f.Protocol)
	if f.Protocol == 17 {
		protocol = "udp"
	} else if f.Protocol == 6 {
		protocol = "tcp"
	}
	if len(f.SrcIP) == net.IPv6len {
		return fmt.Sprintf("%s [%s]:%d->[%s]:%d", protocol, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)
	} else {
		return fmt.Sprintf("%s %s:%d->%s:%d", protocol, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)
	}
}
