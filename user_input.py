#import re


def enter_ip():
    ip = input("enter the IP: ")
    return ip

def ban_ip():
    ip = input("enter the ip range with , ")
    c = ip.split(",")
    return c

def ban_tcp():
    c =[]
    port = input("Enter the TCP port: ")
    if "," in port:
        s =  port.split(",")
        for i in s:
            c.append(int(i))
        return c
    else:
        return port