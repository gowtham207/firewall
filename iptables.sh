iptables -I INPUT -j NFQUEUE --queue-num 1 
iptables -I OUTPUT -j NFQUEUE --queue-num 1 
iptables -I FORWARD -j NFQUEUE --queue-num 1