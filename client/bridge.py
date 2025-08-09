from scapy.all import sniff, IP, ICMP, send
import threading, math, struct

class BridgeException(Exception):
    pass

class PendingPacket():
    def __init__(self, reservedSeqs, expectedSize, messageId):
        self.messageId = messageId
        self.reservedSeqs = reservedSeqs
        self.expectedSize = expectedSize
        self.content = b''
        self.canForward = False
    
    def addContent(self, content):
        self.content += content
    
    def getContent(self):
        return self.content
    
    def hasSeq(self, seq):
        return seq in self.reservedSeqs

ICMP_CHUNK_SIZE = 1468
class Bridge:
    def __init__(self, remote, password, unsafe=False, authorized=False):
        self.remote = remote
        self.pendingPackets = list()
        self.packetsIn = list()
        self.seq = 0
        self.unsafe = unsafe
        self.password = password
        self.authorized = authorized
        self.lastMessageId = 0
    
    def readPacket(self, messageId):
        _packet = None
        while not _packet:
            for packet in self.packetsIn:
                if packet.messageId == messageId:
                    _packet = packet
                    self.packetsIn.remove(packet)
                    break
        return _packet
    
    def getPendingPacketBySeq(self, seq):
        for packet in self.pendingPackets:
            if packet.hasSeq(seq):
                return packet
        return None

    def handlePacket(self, packet):
        if packet.haslayer(ICMP):
            canProcess = False
            icmp = packet[ICMP]

            if icmp.type == 0:
                ip = packet[IP]
                payload = bytes(icmp.payload)
                
                if not self.unsafe and ip.src != self.remote:
                    return

                if not self.authorized:
                    if payload == b'\x00':
                        self.authorized = True
                    elif payload == b'\x01':
                        raise BridgeException('Wrong password provided for bridge')
                    else:
                        raise BridgeException('Got unexpected response from bridge')
                    return

                _packet = self.getPendingPacketBySeq(icmp.seq)

                if not _packet:
                    messageId = int.from_bytes(payload[:2])
                    payload = payload[2:]
                    contentSize = int.from_bytes(payload[:4])
                    content = payload[4:]
                    requiredPacketAmount = math.ceil(contentSize / ICMP_CHUNK_SIZE)
                    _packet = PendingPacket([icmp.seq + i for i in range(0, requiredPacketAmount)], contentSize, messageId)
                    _packet.addContent(content)
                    self.pendingPackets.append(_packet)
                    if len(content) == contentSize:
                        _packet.canForward = True
                else:
                    _packet.addContent(payload)
                    if len(_packet.getContent()) >= _packet.expectedSize:
                        _packet.canForward = True
                
                if _packet.canForward:
                    self.pendingPackets.remove(_packet)
                    self.packetsIn.append(_packet)

    def sendPacket(self, data, build=False):
        if build:   data = self.buildDataPacket(data)
        if len(data) > ICMP_CHUNK_SIZE:
            for i in range(0, len(data), ICMP_CHUNK_SIZE):
                end = i + ICMP_CHUNK_SIZE
                if end > len(data):
                    end = len(data)
                self.sendPacketImpl(data[i:end])
        else:
            self.sendPacketImpl(data)

    def sendPacketImpl(self, data):
        self.seq += 1
        return send(IP(dst=self.remote) / ICMP(type=8, id=0, seq=self.seq) / data, verbose=0)

    def buildDataPacket(self, data, rule=0x01):
        output = struct.pack('>HBI', self.lastMessageId, rule, len(data)) + data
        self.lastMessageId += 1
        return output

    def beginListen(self):
        sniff(filter='icmp', prn=self.handlePacket)

    def run(self):
        threading.Thread(target=self.beginListen).start()
        if not self.authorized:
            self.sendPacket(b'\x01\x09\x02\x06' + bytes(self.password, encoding='utf-8'))
        while not self.authorized:
            pass