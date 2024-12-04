from scapy.all import IP, send, ICMP, Packet, AsyncSniffer

import time


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
        self.responses = []

    def sendPackets(self):
        startTime = time.time()

        asyncFilter = AsyncSniffer(
            count=0,
            filter="icmp and (icmp[0] == 0 or icmp[0] == 11) and src host not 192.168.1.209",
            stop_filter=self.stopFilter,
            lfilter=lambda pck: self.responses.append(pck.getlayer(IP).src),
            timeout=60,
        )

        asyncFilter.start()

        try:
            while asyncFilter.running:

                self.elapsed_time = time.time() - startTime

                if self.elapsed_time >= self.duration:

                    self.responses.append("*")
                    continue

                if self.ttl >= 30:
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
            return self.responses

    # Used for dubbugging use a lamba function for this
    def stopFilter(
        self,
        pck: Packet,
    ) -> bool:  # stop the filter when we get a echo reply message or ttl is >= 30

        print("Src:", pck.getlayer(IP).src)
        print("Dst:", pck.getlayer(IP).dst)
        print("Type:", pck.getlayer(ICMP).type)
        return self.ttlVal >= 30 or (
            pck.haslayer(ICMP) and pck.getlayer(ICMP).type == 0
        )

    def main(self):

        results = self.sendPackets()

        if len(results) != 0:
            print("Trace:", results)


trace = TraceRoute(ipAddress="8.8.8.8")

# The stop filter is not getting called, reduced code duplication by just returning the condition. ALso had lfilter keep track of the ip addresses instead of returning asysnc.result.
# I want to implement it when we have a timeout to keep going until the ttl val is too large

trace.main()
