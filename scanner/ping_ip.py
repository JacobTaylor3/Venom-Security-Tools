
from scapy.all import IP, ICMP, sr1,Raw,send,Packet

import time 

from typing import Optional



def checkDataPacket(response:tuple[Optional[Packet], float])->str:
    if response[0] is None:
        return "No Response"
    
    else:
       return f"Response:{response[0].show()}"
    

def pingIpAdr(ip:str,timeout_pr =8)-> tuple[Optional[Packet], float]:
       
     startTime = time.time() #bytes
    
     response = sr1(IP(dst= ip) /ICMP(),verbose= False)  
    
     endTime = time.time()
    
     elapsedTime = endTime - startTime

     return (response, elapsedTime)
   
   
def sendPing(ipAdr:str):
    
    return checkDataPacket(pingIpAdr(ipAdr))

