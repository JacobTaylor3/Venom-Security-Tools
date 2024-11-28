from scapy.all import IP,sr1,send,ICMP,Packet,sniff,AsyncSniffer

import time



def stopFilter(pck:Packet)-> bool: # stop the filter when we get a echo reply message or ttl is >= 30  
    
    if pck.haslayer(IP):
        if pck.getlayer(IP).ttl >=30:
            return True
    
    
    return pck.haslayer(ICMP) and pck.getlayer(ICMP).type == 0 
    
    
def filterPck(pck:Packet) -> bool:# filter for time exceed icmp return types
    
    return (pck.haslayer(ICMP) and pck.getlayer(ICMP).type== 11)


def traceRoute(ipAdr,ttlPck)-> list[Packet]:
    
    pck = IP(dst = ipAdr,ttl =ttlPck) / ICMP(type = 8) ## sends icmp packets with ttl from 1-30  
    
    asyncFilter = AsyncSniffer(count = 0 ,filter = "icmp", lfilter = stopFilter , stop_filter= stopFilter,timeout = 60)
    
    asyncFilter.start() # starts sniffer, maybe just manually stop the filter research how 
    
    send(pck,verbose = None,count =3) # we will just have to send it 3 times and filter out any common ip addresses
    
    asyncFilter.join()
    
    return asyncFilter.results



def runTraceRoute():
    pckList = []
    
    for i in range(1,30+1):
        pckList.append(traceRoute("8.8.8.8",i))
        print(pckList[i-1][i-1][IP].getlayer(IP).src)



runTraceRoute()