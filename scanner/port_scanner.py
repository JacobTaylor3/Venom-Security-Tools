# SYN ack

# Full TCP connection

from scapy.all import IP, TCP, sr1

import random

import time

# I want to go over packet fragmentation(Go over how nmap implemented there scanner), banner grabbing, and tcp packet data like options and windows, seq, chksum, etc


class PortScanner:

    def __init__(self, ipAdr="", portNum=(0, 0)):

        self.ipAddress = ipAdr
        self.portNumbers = list(range(portNum[0], portNum[1] + 1))
        self.portList = []

    def setIpAddress(self, ip):
        self.ipAddress = ip

    def getIpAddress(self):
        return self.ipAddress

    def resetPortList(self):
        self.portList = []

    def getCurrentPortList(self):
        return self.portList

    def getRandomSeq():
        return random.randint(0, 2**32 - 1)

    def getRandomWindow():
        return random.randint(1024, 65535)

    def SYNScan(self, portNum):

        craftPacket = IP(dst=self.ipAddress, ttl=64, version=4) / TCP(
            dport=portNum,
            sport=50000,
            flags="S",
            chksum=None,
            seq=self.getRandomSeq(),
            options=[("Timestamp", (0, 0))],
            window=self.getRandomWindow(),
        )

        response = sr1((craftPacket), timeout=5)  # timeouts after 5 seconds

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

    def TCPConnectionScan():
        pass

    def fragmentScan():
        pass

    def UDPScan():
        pass

    def grabBanner():
        pass

    def startScan(self, function):

        portNumCopy = list(self.portNumbers)

        random.shuffle(portNumCopy)
        for port in range(0, len(self.portNumbers)):
            function(portNumCopy[port])
            time.sleep(random.uniform(0.5, 2.0))


test = PortScanner("192.168.1.172", (1, 80))

test.startScan(test.SYNScan)

print(test.portList)
