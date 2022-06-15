#!/usr/bin/python3
import scapy.all as scapy
import netfilterqueue
import user_input

ip = user_input.enter_ip()
block = user_input.ban_ip()
tcp_port = user_input.ban_tcp()
udp_port = user_input.ban_udp()

def report(val):
    a = open("report.txt","a")
    if len(val) == 1:
        c = "\n block ip  from "+val[0]
        a.write(c)
    
    else:
        c = "\n request from \nip: "+val[0]+"\nport:"+val[1]
        a.write(c)
    



def firewall(pkt):
    #print(pkt)
    sca = scapy.IP(pkt.get_payload())
    if sca.haslayer(scapy.ICMP):
        if sca[scapy.ICMP].type == 8 and sca.dst == ip:
            print("request from "+str(sca.src))  
            c = [str(sca.src)]
            report(c)
            pkt.drop()
            return
        else:
            
            pkt.accept()
            return
    
    if sca.src in block:
        print("blocking the ip"+str(sca.src))
        c = [str(sca.src)]
        report(c)
        pkt.drop()
        return 
   
    if sca.haslayer(scapy.TCP):
        if sca[scapy.TCP].dport in tcp_port and sca[scapy.IP].src!=ip:
            #print(sca.show())
            port = sca[scapy.TCP].dport
            ip_add = sca.src
            print("port "+str(port)+"  TCP accessed by "+str(ip_add))
            c = [str(ip_add),str(port)]
            report(c)
            pkt.drop()
            return

    if sca.haslayer(scapy.UDP):
        if sca[scapy.UDP].dport in udp_port and sca[scapy.IP].src!=ip:
            
            port = sca[scapy.UDP].dport
            ip_add = sca.src
            print("port "+str(port)+" accessed by "+str(ip_add))
            c = [str(ip_add),str(port)]
            report(c)
            pkt.drop()
            return 

    #print(sca.show())  
    pkt.accept()
   
queue = netfilterqueue.NetfilterQueue()
queue.bind(1,firewall)
queue.run()
