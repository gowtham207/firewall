#!/usr/bin/python3
import scapy.all as scapy
import netfilterqueue
import user_input

ip = user_input.enter_ip()
block = user_input.ban_ip()
tcp_port = user_input.ban_tcp()
def firewall(pkt):
    #print(pkt)
    sca = scapy.IP(pkt.get_payload())
    if sca.haslayer(scapy.ICMP):
        if sca[scapy.ICMP].type == 8 and sca.dst == ip:
            print("request from "+str(sca.src))  
            pkt.drop()
            return
        else:
            pkt.accept()
            return
    
    if sca.src in block:
        print("blocking the ip"+str(sca.src))
        pkt.drop()
        return 
   
    if sca.haslayer(scapy.TCP):
        print(sca.show()) 
    #print(sca.show())  
    pkt.accept()




      

    
    
    
    


queue = netfilterqueue.NetfilterQueue()
queue.bind(1,firewall)
queue.run()