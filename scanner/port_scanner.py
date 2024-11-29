# SYN ack

# Full TCP connection

from scapy.all import IP, send, ICMP, Packet, AsyncSniffer, TCP

import time


class PortScanner:

    # 1- 40

    def __init__(self, ipAdr="", portNum=(0, 0), duration=180):

        self.ipAddress = ipAdr
        self.portNumbers = portNum
        self.OpenPorts = []
        self.duration = duration

    def sendSYNPackets(self):
        startTime = time.time()

        asyncFilter = AsyncSniffer(
            count=0,
            filter=(
                f"tcp[tcpflags] & tcp-ack != 0 and portrange {self.portNumbers[0]}-{self.portNumbers[1]} "
                f"and src host {self.ipAddress} "
                f"and not src host 192.168.1.209"
            ),
            timeout=180,
        )

        asyncFilter.start()

        send(
            IP(dst=self.ipAddress, ttl=64) / TCP(dport=self.portNumbers, flags="S"),
            realtime=True,
        )

        time.sleep(60)

        asyncFilter.stop()
        
        asyncFilter.su

        return asyncFilter.results


portscan = PortScanner("192.168.1.172", (1, 1000))

(portscan.sendSYNPackets())
