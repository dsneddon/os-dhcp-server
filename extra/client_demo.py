# example UDP client sender, call with "python client.py <port>"
import socket, sys, time

sendto_ip = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #Internet, UDP
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(('', 670))
print "Sending UDP messages to %s:%s" % (sendto_ip, port)
i = 1
while 1:
    data = repr(time.time()) + ' Ping Seq %d' % (i)
    print "Sending data: %s" % data
    s.sendto(data, (sendto_ip,port))
    i += 1
    time.sleep(1)
