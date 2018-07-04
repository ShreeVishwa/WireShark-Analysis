import dpkt
from collections import defaultdict
f = open('http_1080.pcap')
pkt = dpkt.pcap.Reader(f)

s_ports = []
t_stamps = []
total_bytes = 0
num_pkts = 0
num_get_req = 0
req_dport = 0
requests = defaultdict(list)
response = defaultdict(list)
mapping = defaultdict(list)
for buff in pkt:
    data = buff[1]
    if num_pkts == 0:
        req_dport = int("".join(data[36:38]).encode("hex"),16)
        # print req_dport
    num_pkts += 1
    total_bytes += len(data)
    t_stamps.append(buff[0])
    s_port = int("".join(data[34:36]).encode("hex"),16)
    d_port = int("".join(data[36:38]).encode("hex"),16)
    s_ports.append(s_port)
    if s_port != req_dport:
        mapping[(s_port,d_port)].append(data)
    else:
        mapping[(s_port,d_port)].append(data)

req_ports = list(set(s_ports))
ack_nos = []
req_ports.remove(req_dport)
count1 = 0
for port in req_ports:
    req = mapping.get((port,req_dport))
    res = mapping.get((req_dport,port))
    for data in req:
        if "GET" in data:
            num_get_req += 1
            requests[port].append(data)
            # print str(int("".join(data[34:36]).encode("hex"),16))
            # print str(int("".join(data[36:38]).encode("hex"),16))
            # print str(int("".join(data[38:42]).encode("hex"),16))
            break
    for data in res:
        if int("".join(data[47]).encode("hex")) == 10 and int("".join(data[47]).encode("hex")) != 11:
            response[port].append(data)

count_1 = 1
for port in requests.keys():
    # print requests[port]
    # break
    data = requests[port]
    # print data[0]
    print "Request " + str(count_1)
    print "Source : " + str(int("".join(data[0][34:36]).encode("hex"),16))
    print "Destination : " + str(int("".join(data[0][36:38]).encode("hex"),16))
    print "Seq : " + str(int("".join(data[0][38:42]).encode("hex"),16))
    print "Ack : " + str(int("".join(data[0][42:46]).encode("hex"),16))

    data1 = response[port]
    for i in xrange(len(data1)):
        print "Response " + str(count_1)
        print "Source : " + str(int("".join(data1[i][34:36]).encode("hex"),16))
        print "Destination : " + str(int("".join(data1[i][36:38]).encode("hex"),16))
        print "Seq : " + str(int("".join(data1[i][38:42]).encode("hex"),16))
        print "Ack : " + str(int("".join(data1[i][42:46]).encode("hex"),16))

    count_1 += 1

if  len(req_ports) == 18:
    print "The HTTP Protocol being used is HTTP 1.0"
elif len(req_ports) == 7 or len(req_ports) == 6:
    print "The HTTP Protocol being used is HTTP 1.1"
elif len(req_ports) == 1 or len(req_ports) == 2:
    print "The HTTP Protocol being used is HTTP 2.0"

print "Time taken is : " + str(t_stamps[len(t_stamps)-1] - t_stamps[0])
print "Num of bytes is : " + str(total_bytes)
print "Number of pkts is :" + str(num_pkts)
