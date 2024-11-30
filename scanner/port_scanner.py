# SYN ack

# Full TCP connection

from scapy.all import IP, TCP, sr1

import random

import time

#I want to go over packet fragmentation(Go over how nmap implemented there scanner, what is TCP Retransmission), banner grabbing, and tcp packet data like options and windows, seq, chksum, etc


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

    def getRandomSeq(self):
        return random.randint(0, 2**32 - 1)

    def getRandomWindow(self):
        return random.randint(1024, 65535)

    def scanCommonPorts(self):
        self.portNumbers = [
            20,  # FTP Data Transfer
            21,  # FTP Control
            22,  # SSH Remote Login Protocol
            23,  # Telnet
            25,  # SMTP (Email)
            53,  # DNS
            67,  # DHCP (Server)
            68,  # DHCP (Client)
            69,  # TFTP
            80,  # HTTP
            110,  # POP3 (Email)
            119,  # NNTP (Usenet)
            123,  # NTP (Network Time Protocol)
            135,  # Microsoft RPC
            137,  # NetBIOS Name Service
            138,  # NetBIOS Datagram Service
            139,  # NetBIOS Session Service
            143,  # IMAP (Email)
            161,  # SNMP
            194,  # IRC
            389,  # LDAP
            443,  # HTTPS
            445,  # Microsoft-DS (Active Directory, SMB)
            465,  # SMTPS (Secure SMTP)
            514,  # Syslog
            515,  # LPD/LPR (Printer Service)
            587,  # SMTP (Email Submission)
            631,  # Internet Printing Protocol
            636,  # LDAPS (Secure LDAP)
            873,  # Rsync
            993,  # IMAPS (Secure IMAP)
            995,  # POP3S (Secure POP3)
            1080,  # SOCKS Proxy
            1194,  # OpenVPN
            1433,  # Microsoft SQL Server
            1521,  # Oracle Database
            1723,  # PPTP VPN
            2049,  # NFS
            2082,  # cPanel (HTTP)
            2083,  # cPanel (HTTPS)
            3306,  # MySQL Database
            3389,  # Remote Desktop Protocol (RDP)
            5432,  # PostgreSQL Database
            5900,  # VNC Remote Desktop
            6379,  # Redis
            8080,  # HTTP Alternate
            8443,  # HTTPS Alternate
            10000,  # Webmin
            27017,  # MongoDB
            50000,  # SAP Router
        ]

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
            self.portList.append(
                {"port": portNum, "status": "filtered/firewall blocking"}
            )

        # the response got received now need to check response

        else:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                self.portList.append({"port": portNum, "status": "open"})
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                self.portList.append({"port": portNum, "status": "closed"})
            else:
                self.portList.append(
                    {"port": portNum, "status": "closed nothing last else"}
                )

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

        data = self.portList
        self.resetPortList()
        return data


test = PortScanner("192.168.1.1")

test.scanCommonPorts()

print(test.startScan(test.SYNScan))
