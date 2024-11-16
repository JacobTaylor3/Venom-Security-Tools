
from scapy.all import IP, ICMP, sr1,Packet

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
   
   
def sendPing(ipAdr:str,count= 4):
    output = []
    for _i in range(0,count):
        output.append(checkDataPacket(pingIpAdr(ipAdr)))
        
    return formatPacketLoss(output)

def formatPacketLoss(outputArr:List[str]):
    copyArr = outputArr[:]
    copyArr.append(f"Packet Loss:{checkPacketLoss(copyArr)}%")
    return copyArr
    
    
def checkPacketLoss(outputArr:List[tuple[Optional[Packet], float]]):
    totalSent = len(outputArr)
    pckLoss = 0
    
    for response in outputArr:
       if response == "Destination unreachable":
           pckLoss+=1
           

           
    return round(((pckLoss/totalSent) * 100),0)


print(sendPing("192.168.1.92"))


