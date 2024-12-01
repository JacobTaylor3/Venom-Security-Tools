from scapy.all import IP, send, ICMP, Packet, AsyncSniffer

import time

import ping_ip



class TraceRoute:

    def __init__(
        self,
        duration=60,
        ipAddress="",
    ):

        self.ipAddress = ipAddress
        self.ttlVal = 1
        self.elapsedTime = 0  # time for timeout
        self.duration = duration

    def sendPackets(self):
        startTime = time.time()

        asyncFilter = AsyncSniffer(
            count=0,
            filter="icmp and (icmp[0] == 0 or icmp[0] == 11) and src host not 192.168.1.209",
            stop_filter=self.stopFilter,
            timeout=60,
        )

        asyncFilter.start()

        try:
            while asyncFilter.running:

                self.elapsed_time = time.time() - startTime

                if self.elapsed_time >= self.duration or self.ttlVal >= 30:
                    raise TimeoutError(
                        f"Traceroute to {self.ipAddress} timed out after {self.duration} seconds."
                    )

                send(
                    IP(dst=self.ipAddress, ttl=self.ttlVal) / ICMP(type=8),
                    realtime=True,
                    inter=2,
                    verbose=False,
                )
                self.ttlVal += 1

        except TimeoutError as error:
            print(error.args)
            asyncFilter.stop()

        finally:
            return asyncFilter.results

    def stopFilter(
        self,
        pck: Packet,
    ) -> bool:  # stop the filter when we get a echo reply message or ttl is >= 30

        print("Src:", pck.getlayer(IP).src)
        print("Dst:", pck.getlayer(IP).dst)
        print("Type:", pck.getlayer(ICMP).type)
        if self.ttlVal >= 30 or (pck.haslayer(ICMP) and pck.getlayer(ICMP).type == 0):
            return True

        return False

    def formatData(self, data):
        ipList = []
        if data:
            for pck in data:
                ipList.append(pck.getlayer(IP).src)
        return ipList

    def main(self):

        results = self.sendPackets()
        format = self.formatData(results)

        if format is not None:
            print("Trace:", format)


trace = TraceRoute(ipAddress="5.5.5.5")

trace.main()
