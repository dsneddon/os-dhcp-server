# example UDP receiver server, call with python server.py <port>
import socket, sys, IN

listen_ip = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #Internet, UDP
#s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind((listen_ip, port))
print "Listening for UDP messages on %s:%s" % (listen_ip, port)
while 1:
    data,addr = s.recvfrom(1024)
    print 'Ping received from %s: %s' % (addr, data)
