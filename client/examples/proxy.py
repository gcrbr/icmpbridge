import socket, threading, bridge, argparse

class HTTPProxy:
    def __init__(self, port, bridgeSettings):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bridgeSettings = bridgeSettings
        self.bridges = dict()
        self.needAuth = True
    
    def handleClient(self, conn, addr):
        addr = addr[0]
        if addr not in self.bridges:
            self.bridges[addr] = bridge.Bridge(*self.bridgeSettings)
            self.bridges[addr].run()
            self.needAuth = False
            self.bridgeSettings[3] = not self.needAuth
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                messageId = self.bridges[addr].lastMessageId
                self.bridges[addr].sendPacket(data, build=True)
                replyPacket = self.bridges[addr].readPacket(messageId)
                conn.send(replyPacket.getContent())
        except Exception as e:
            print(f'[handleClient] An error has occured: {e}')

    def run(self):
        try:
            self.sock.bind(('0.0.0.0', self.port))
            self.sock.listen(5)

            while True:
                conn, addr = self.sock.accept()
                threading.Thread(target=self.handleClient, args=(conn, addr,)).start()
        except Exception as e:
            print(f'[run] An error has occured: {e}')
            
if __name__ == '__main__':
    print('HTTP Proxy via icmpbridge :: created by @gcrbr')
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--remote', type=str, help='Address of the ICMP bridge', required=True)
    parser.add_argument('-pw', '--password', type=str, help='Password of the icmpbridge server', required=True)
    parser.add_argument('-u', '--unsafe', type=bool, help='Enable unsafe mode: listens to ICMP packets from any address')
    parser.add_argument('-p', '--port', type=int, help='HTTP proxy port', default=8080)
    args = vars(parser.parse_args())

    print(f'Listening on port {args["port"]}')

    settings = [args['remote'], args['password'], args['unsafe'], False]
    proxy = HTTPProxy(args['port'], settings)
    proxy.run()