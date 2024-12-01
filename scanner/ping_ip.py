from scapy.all import IP, ICMP, sr1,Packet

import time

from typing import Optional, List


class PingIP:

    def __init__(self, ipAdr=""):
        self.ipAdr = ipAdr

    def __checkDataPacket(self,response: tuple[Optional[Packet], float]) -> str:
        if response[0] is not None and response[0].haslayer(ICMP):

            PACKET = response[0][IP]

            src = PACKET.src
            time = response[1]
            ttl = PACKET.ttl

            return f"Reply from: {src}  time: {time} ms  TTL: {ttl}"

        else:
            return "Destination unreachable"

    def pingIpAdr(
        self
    ) -> tuple[
        Optional[Packet], float
    ]:  # test this function for testing make sure its not None

        startTime = time.time()  # bytes

        response = sr1(IP(dst=self.ipAdr) / ICMP(), verbose=False, timeout=5)

        endTime = time.time()

        elapsedMiliseconds = round((endTime - startTime) * 1000, 3)

        return (response, elapsedMiliseconds)

    def sendPing(self):
        output = []
        for _i in range(0, 4):
            output.append(self.checkDataPacket(self.pingIpAdr()))

        output.append(f"Packet Loss:{round(self.checkPacketLoss(output),2)}%")

        return output

    def __checkPacketLoss(self,outputArr: List[tuple[Optional[Packet], float]]):
        totalSent = len(outputArr)
        pckLoss = 0

        for response in outputArr:
            if response[0] is None:
                pckLoss += 1

        return pckLoss / totalSent


