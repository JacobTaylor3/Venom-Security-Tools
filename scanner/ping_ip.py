
from scapy.all import IP, ICMP, sr1,Raw

import time 




def pingIP(ip:str,time =8)-> str:
    
    bytes = Raw(b"A" * 32), startTime = time.time() #bytes
    
    response = sr1(IP(dst= ip,ttl = time)/ICMP()/ bytes) # if None, no response 
    
    endTime = time.time()
    
    elapsedTime = endTime - startTime
    
    if response:
       return f"Reply from {ip}: bytes{bytes} time:{elapsedTime* 1000} ttl:{time}" # response 
        
    else: # no response
        return f"Destination:{ip} unreachable"
        
