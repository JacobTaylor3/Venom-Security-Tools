# SYN ack

# Full TCP connection

from scapy.all import IP, send, ICMP, Packet, AsyncSniffer, TCP, sr1, sniff

import random

import time


class PortScanner:

    # 1- 40

    def __init__(self, ipAdr="", portNum=(0, 0), duration=180):

        self.ipAddress = ipAdr
        self.portNumbers = list(range(portNum[0], portNum[1] + 1))
        self.portList = []
        self.duration = duration

    def sendSYNPacket(self, portNum):
        randomSeq = random.randint(0, 2**32 - 1)

        craftPacket = IP(dst=self.ipAddress, ttl=64, version=4) / TCP(
            dport=portNum,
            sport=50000,
            flags="S",
            chksum=None,
            seq=randomSeq,
            options=[("Timestamp", (0, 0))],
        )

        response = sr1(craftPacket, timeout=5)  # timeouts after 5 seconds

        if response is None:
            self.portList.append({"port": portNum, "status": "filtered"})

        # the response got received now need to check response

        else:
            if (
                response.haslayer(TCP)
                and response.getlayer(TCP).sprintf("%TCP.flags%") == "SA"
            ):
                self.portList.append({"port": portNum, "status": "open"})
            elif (
                response.haslayer(TCP)
                and response.getlayer(TCP).sprintf("%TCP.flags%") == "R"
            ):
                self.portList.append({"port": portNum, "status": "closed"})
            else:
                self.portList.append({"port": portNum, "status": "closed"})

    def sendPackets(self):

        length = len(self.portNumbers)
        for _i in range(0, length):
            portNumber = self.portNumbers.pop(0)
            self.sendSYNPacket(portNumber)
            time.sleep(2)


test = PortScanner("192.168.1.172", (1, 80))

test.sendPackets()
print(test.portList)
