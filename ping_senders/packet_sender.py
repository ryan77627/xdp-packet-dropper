from scapy.all import Ether, IP, UDP, sendp

input_ip = input("Enter destination IP: ")

p = Ether()/IP(dst=input_ip, src='223.255.254.115')/UDP(b"A Payload")

sendp(p)
