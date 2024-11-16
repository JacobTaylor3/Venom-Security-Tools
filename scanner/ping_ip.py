
from scapy.all import IP, ICMP, sr1,Raw,send,Packet

import time 

from typing import Optional,List



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
    
     response = sr1(IP(dst= ip) /ICMP(),verbose= False,timeout=5)  
    
     endTime = time.time()
    
     elapsedMiliseconds = round((endTime - startTime)* 1000, 3)
     
     return (response, elapsedMiliseconds)
   
   
def sendPing(ipAdr:str):
    output = []
    for _i in range(0,4):
        output.append(checkDataPacket(pingIpAdr(ipAdr)))
        
    output.append(f"Packet Loss:{round(checkPacketLoss(output),2)}%")
     
    return output

def checkPacketLoss(outputArr:List[tuple[Optional[Packet], float]]):
    totalSent = len(outputArr)
    pckLoss = 0
    
    for response in outputArr:
       if response[0] is None:
           pckLoss+=1
           
    return pckLoss/totalSent



print(sendPing("1.1.1.1"))


