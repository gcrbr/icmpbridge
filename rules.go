package main

import (
	"os"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"net"
	"io"
	"strings"
	"encoding/binary"
)

type Forward struct {
	Protocol string `yaml:"protocol"`
	Address string	`yaml:"address"`
	Port     int    `yaml:"port"`
}

type Rule struct {
	Rule    int     `yaml:"rule"`
	Forward Forward `yaml:"forward"`
	Log     bool    `yaml:"log"`
}

var rules []Rule

func parseRules(rulesFile string) {
	data, err := os.ReadFile(rulesFile)

	if err != nil {
		log.Printf("Could not read rules file: %s\n", err)
		return
	}

	err = yaml.Unmarshal(data, &rules)
	if err != nil {
		log.Printf("Could not parse YAML from rules file: %s\n", err)
		return
	}
}

func buildDataPacket(data []byte, messageId uint16) []byte {
	msgId := make([]byte, 2)
	binary.BigEndian.PutUint16(msgId, messageId)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(data)))
	msgId = append(msgId, length...)
	msgId = append(msgId, data...)
	return msgId
}

func startBridge(protocol string, src uint32, address string, port int, packet *PendingPacket, logging bool) {
	conn, err := net.Dial(protocol, fmt.Sprintf("%s:%d", address, port))
	if err != nil {
		log.Printf("Could not start bridge: %s\n", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(packet.receivedData)
	if err != nil {
		log.Printf("Could not send data to bridge: %s\n", err)
		return
	}

	var reply []byte
    buf := make([]byte, 4096)

    for {
        n, err := conn.Read(buf)
        if n > 0 {
            reply = append(reply, buf[:n]...)
        }
        if err != nil {
            if err == io.EOF {
                break
            }
            log.Printf("Could not read data from bridge: %s\n", err)
            return
        }
    }

	sendICMPPacket(src, buildDataPacket(reply, packet.messageId))
	if logging {
		log.Printf("[\033[0;34mBRIDGE:%s\033[0m] %s:%d, size=%d\n", strings.ToUpper(protocol), address, port, len(reply))
	}
}

func handlePacket(src uint32, packet *PendingPacket) {
	for _, rule := range rules {
		if packet.ruleId == uint8(rule.Rule) {
			if rule.Log {
				log.Printf("[\033[0;34mCALL\033[0m] client=%s, rule=%d, size=%d\n", ipToString(src), rule.Rule, len(packet.receivedData))
			}
			if (rule.Forward != Forward{}) {
				if rule.Forward.Protocol == "tcp" || rule.Forward.Protocol == "udp" {
					startBridge(rule.Forward.Protocol, src, rule.Forward.Address, rule.Forward.Port, packet, rule.Log)
				}
			}
		}
	}
}