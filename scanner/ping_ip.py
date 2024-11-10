
from scapy.all import IP, ICMP, sr1,Raw,send,Packet

import time 

from typing import Optional




def checkDataPacket(response:tuple[Optional[Packet], float])->str:
    if response[0] is not None and response[0].haslayer(ICMP):

       PACKET = response[0][IP]
       
       src = PACKET.src
       time = response[1]
       ttl = PACKET.ttl
       
       return f"Reply from: {src}  time: {time} ms  TTL: {ttl}"
    
    else:
        return "Destination unreachable"
       
    

def pingIpAdr(ip:str,timeout_pr =8)-> tuple[Optional[Packet], float]: #test this function for testing make sure its not None
       
     startTime = time.time() #bytes
    
     response = sr1(IP(dst= ip) /ICMP(),verbose= False)  
    
     endTime = time.time()
    
     elapsedSeconds = endTime - startTime
     
     millisecondsElapsed = round(elapsedSeconds,3)

     return (response, millisecondsElapsed)
   
   
def sendPing(ipAdr:str):
    output = []
    for _i in range(0,3):
        output.append(checkDataPacket(pingIpAdr(ipAdr)))
     
    return output


print(sendPing("8.8.8.8"))