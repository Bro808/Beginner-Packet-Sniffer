
import socket  #import required modules

#INET raw socket. First Parameter is the INET raw socket, next is the type of socket, the last is the protocol of the package
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

#Infinite loop to receive data from the socket
while True:
    print(s.recvfrom(65565)) #65565 is the max buffer size

#run on linux: sudo python3 Basic_PacketSniff.py