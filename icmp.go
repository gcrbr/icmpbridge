package main

import (
	"log"
	"github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
	"encoding/binary"
	"time"
	"net"
    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
	"math"
	"slices"
	"sync"
)

type ICMPPacket struct {
	address uint32
	sequence uint16
	identifier uint16
	payload []byte
}

type PendingPacket struct {
	messageId uint16
	ruleId uint8
	receivedData []byte
	expectedSize uint32
	reservedSeqs []uint16
	canForward bool
}

type Client struct {
	key []byte
	lastReqTime int64
	packets []PendingPacket
	lastSeq uint16
	lastId uint16
	lastMessageId uint16
}

var clients map[uint32]*Client
var clientsMutex sync.Mutex

const ICMP_CHUNK_SIZE = 1468

var packetChannel chan ICMPPacket

func getPacketByReservedSeq(addr uint32, seq uint16) *PendingPacket {
	clientsMutex.Lock()
	client, _ := clients[addr]
	for _, packet := range client.packets {
		if slices.Contains(packet.reservedSeqs, seq) {
			return &packet
		}
	}
	clientsMutex.Unlock()
	return nil
}

func sendICMPPacket(dst uint32, content []byte) {
	clientsMutex.Lock()
	client, exists := clients[dst]
	clientsMutex.Unlock()
	
	if len(content) > ICMP_CHUNK_SIZE {
		for i := 0; i < len(content); i += ICMP_CHUNK_SIZE {
			end := i + ICMP_CHUNK_SIZE
			if end > len(content) {
				end = len(content)
			}
			if exists {
				clientsMutex.Lock()
				client.lastSeq = (client.lastSeq + uint16(1)) % 65535
				currentSeq := client.lastSeq
				clientsMutex.Unlock()
				sendICMPPacketImpl(dst, content[i:end], currentSeq)
			}else {
				sendICMPPacketImpl(dst, content[i:end], 0)
			}
		}
	}else {
		if exists {
			clientsMutex.Lock()
			client.lastSeq = (client.lastSeq + uint16(1)) % 65535
			currentSeq := client.lastSeq
			clientsMutex.Unlock()
			sendICMPPacketImpl(dst, content, currentSeq)
		}else {
			sendICMPPacketImpl(dst, content, 0)
		}
	}
}

func sendICMPPacketImpl(dst uint32, content []byte, seq uint16) {
	lastId := 0

	clientsMutex.Lock()
	client, exists := clients[dst]
	if exists {
		lastId = int(client.lastId)
	}
	clientsMutex.Unlock()

	message := &icmp.Message{
        Type: ipv4.ICMPTypeEchoReply,
        Code: 0,
        Body: &icmp.Echo{
            ID:   lastId,
            Seq:  int(seq),
            Data: []byte(content),
        },
    }

    msgBytes, err := message.Marshal(nil)
    if err != nil {
        log.Printf("Could not build ICMP response: %s\n", err)
        return
    }

    addr, err := net.ResolveIPAddr("ip", ipToString(dst))
    if err != nil {
		log.Printf("Could not resolve address '%s': %s\n", ipToString(dst), err)
        return
    }

    conn, err := net.DialIP("ip4:icmp", nil, addr)
    if err != nil {
        log.Printf("Could not connect to address '%s': %s\n", ipToString(dst), err)
        return
    }
    defer conn.Close()

    _, err = conn.Write(msgBytes)
    if err != nil {
		log.Printf("Could not send ICMP packet to address '%s': %s", ipToString(dst), err)
		return
    }
}

func handleICMPPacket(icmpPacket ICMPPacket) {
	clientsMutex.Lock()
	client, exists := clients[icmpPacket.address]
	clientsMutex.Unlock()
	payload := icmpPacket.payload

	if exists {
		if len(payload) >= 4 && payload[0] == 0x01 && payload[1] == 0x09 && payload[2] == 0x02 && payload[3] == 0x06 {
			sendICMPPacket(icmpPacket.address, []byte(AUTHORIZED))
			return
		}

		if len(payload) == 0 {
			return
		}

		clientsMutex.Lock()
		client.lastId = icmpPacket.identifier
		client.lastReqTime = time.Now().Unix()
		clientsMutex.Unlock()

		_packet := getPacketByReservedSeq(icmpPacket.address, icmpPacket.sequence)
		if _packet == nil {			
			_packet = &PendingPacket{}

			_packet.messageId = binary.BigEndian.Uint16(payload[:2])
			payload = payload[2:]

			_packet.ruleId = payload[0]
			_packet.receivedData = make([]byte, 0)
			_packet.canForward = false
			_packet.reservedSeqs = make([]uint16, 0)

			payload = payload[1:]
			contentSize := (binary.BigEndian.Uint32(payload[:4]))
			content := payload[4:]

			_packet.expectedSize = contentSize

			if contentSize == 0 {
				return
			}

			if uint32(len(content)) < contentSize {
				requiredAmountPackets := int(math.Ceil(float64(contentSize) / float64(ICMP_CHUNK_SIZE)))
				for i := 0; i < requiredAmountPackets; i++ {
					_packet.reservedSeqs = append(_packet.reservedSeqs, icmpPacket.sequence + uint16(i % 255))
				}
			}else {
				_packet.receivedData = content
				_packet.canForward = true
			}

			clientsMutex.Lock()
			client.packets = append(client.packets, *_packet)
			clientsMutex.Unlock()
		}else {
			_packet.receivedData = append(_packet.receivedData, icmpPacket.payload...)
			if(len(_packet.receivedData) >= int(_packet.expectedSize)) {
				_packet.canForward = true
			}
		}

		if(_packet.canForward) {
			handlePacket(icmpPacket.address, _packet)
			clientsMutex.Lock()
			client.packets = removeElement(client.packets, _packet).([]PendingPacket)
			clientsMutex.Unlock()
		}
	}else {
		if payload[0] == 0x01 && payload[1] == 0x09 && payload[2] == 0x02 && payload[3] == 0x06 {
			payload := payload[4:]
			if string(payload) == serverPassword {
				clientsMutex.Lock()
				clients[icmpPacket.address] = &Client{key: nil, packets: make([]PendingPacket, 0), lastReqTime: time.Now().Unix(), lastSeq: 0, lastMessageId: 0}
				clientsMutex.Unlock()
				sendICMPPacket(icmpPacket.address, []byte(AUTHORIZED))
				log.Printf("client %s authorized\n", ipToString(icmpPacket.address))
			}else {
				sendICMPPacket(icmpPacket.address, []byte(UNAUTHORIZED))
			}
		}
	}
}

func listenToICMP(_interface string) {
	handle, err := pcap.OpenLive(_interface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Could not listen on interface %s: %s\n", _interface, err)
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter("icmp")
	if err != nil {
		log.Printf("Could not set ICMP filter: %s\n", err)
		return
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ipv4, _ := ipLayer.(*layers.IPv4)
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
					receivedPacket := ICMPPacket{}
					receivedPacket.address = ipToUint32(ipv4.SrcIP)
					receivedPacket.sequence = icmp.Seq
					receivedPacket.identifier = icmp.Id
					receivedPacket.payload = icmp.Payload
					packetChannel <- receivedPacket
				}
			}
		}
	}
}

func packetWorker() {
	packetChannel = make(chan ICMPPacket, 1000)
	const workerCount = 10

	for i := 0; i < workerCount; i++ {
		go func() {
			for pkt := range packetChannel {
				handleICMPPacket(pkt)
			}
		}()
	}
}

func initICMPService(_interface *string) {
	clients = make(map[uint32]*Client)
	packetWorker()
	listenToICMP(*_interface)
}