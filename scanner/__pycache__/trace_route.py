from scapy.all import IP, send, ICMP, Packet, AsyncSniffer


def filterPck(pck: Packet) -> bool:  # filter for time exceed icmp return types
    print("Src:", pck.getlayer(IP).src)
    print("Dst:", pck.getlayer(IP).dst)
    print("Type:", pck.getlayer(ICMP).type)
    return (
        pck.haslayer(ICMP)
        and pck.getlayer(ICMP).type == 11
        or pck.getlayer(ICMP).type == 0
    )


def traceRoute(ipAdr) -> list[Packet]:

    ttlVal = 1
    flag = True

    def stopFilter(
        pck: Packet,
    ) -> bool:  # stop the filter when we get a echo reply message or ttl is >= 30
        nonlocal flag

        if ttlVal >= 30 or (pck.haslayer(ICMP) and pck.getlayer(ICMP).type == 0):
            flag = False
            return True

        return False

    asyncFilter = AsyncSniffer(
        count=0,
        filter="icmp and (icmp[0] == 0 or icmp[0] == 11) and src host not 192.168.1.209",
        lfilter=filterPck,
        stop_filter=stopFilter,
        timeout=60,
    )

    asyncFilter.start()  # starts sniffer, maybe just manually stop the filter research how

    while flag and ttlVal <= 30:

        send(
            IP(dst=ipAdr, ttl=ttlVal) / ICMP(type=8),
            realtime=True,
            inter=2,
            verbose=False,
        )  # we will just have to send it 3 times and filter out any common ip addresses
        ttlVal += 1

    return asyncFilter.results


# Testing
x = traceRoute("208.67.222.222")

print(len(x))

for packet in x:
    print(packet.getlayer(IP).src)
