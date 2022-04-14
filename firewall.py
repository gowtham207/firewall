#!/usr/bin/python3
import scapy.all as scapy
import netfilterqueue
import user_input

ip = "192.168.2.129"
block = "10.0.2.1"
tcp_port = [22]
udp_port = [22]
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
        if sca[scapy.TCP].dport in tcp_port:
            port = sca[scapy.TCP].dport
            ip_add = sca.src
            print("port "+str(port)+" accessed by "+str(ip_add))
            pkt.drop()
            return

    if sca.haslayer(scapy.UDP):
        if sca[scapy.UDP].dport in udp_port:
            port = sca[scapy.UDP].dport
            ip_add = sca.src
            print("port "+str(port)+" accessed by "+str(ip_add))
            pkt.drop()
            return 

    #print(sca.show())  
    pkt.accept()




      

    
    
    
    


queue = netfilterqueue.NetfilterQueue()
queue.bind(1,firewall)
queue.run()