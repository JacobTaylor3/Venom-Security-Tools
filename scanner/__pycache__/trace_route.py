from scapy.all import IP,sr1,send,ICMP,Packet,sniff,AsyncSniffer

import time




def filterICMPTime():

    filter = f"icmp and icmp[0] == 11"
    
    sniff()
    


#going to bed, maybe use sr1 to send and wait for one packet?, then check what the syntax is for getting icmp banner info like echo reply and time- exceeded is it code or type??


#TraceRoute for ICMP version, we send packets with IP protocol, and sniff filters these and gets all the ICMP packets that come back
#Then I filter these packets by the the type of ICMP protocol is being used.
def recordICMPIncoming(ipAdr,maxTTL=30):


    ttlCount:int = 1 #initial time to live value 
        
    t= AsyncSniffer(filter = "icmp",stop_filter= lambda x: (x.haslayer(ICMP) and x[ICMP].code ==0) or x[ICMP].code ==0) # filtering for icmp and when the recived packed is an echo-reply then we stop, need to fiure out destination unreachable
    
    t.start()
    
    while ttlCount <= maxTTL:
        
        response:Packet = send(IP(dst =ipAdr,ttl = ttlCount),count =1)
        
        
    
        
        
        
#If im sending packets to a network that filters ICMP packets run the UDP traceroute version??
        
        
        
        
        
        
        
    
   
           
        
            
        
        
        
            
    
        




print(recordTrace("8.8.8.8"))
        
        
        
        
            
    
    
        
        
        
    
    
    
    
    


