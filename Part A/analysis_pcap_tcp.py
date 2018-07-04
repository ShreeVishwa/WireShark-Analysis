def compute_rtt(total_rtt,key):
    end = 0
    ack_pkt = ack_port.get(key)
    sent_pkt = sent_port.get(tuple(reversed(key)))
    for i in xrange(len(ack_pkt)):
        # c += 1
        time_st = sent_pkt[end][1]
        # print end
        for j in xrange(end,len(sent_pkt)):
            if sent_pkt[j][0] < ack_pkt[i][0]:
                continue
            else:
                end_time = ack_pkt[i][1]
                end = j
                total_rtt[key[1]] += (end_time - time_st)
                break
    return total_rtt[key[1]]/(len(ack_pkt) + len(sent_pkt))

import dpkt
from collections import defaultdict
f = open('assignment2.pcap')
pkt = dpkt.pcap.Reader(f)
count = []
sd_pairs = {}
ack_counts = {}
scaling_factor = {}
throughput = {}
sent_port = defaultdict(list)
ack_port = defaultdict(list)
source_port = []
s_time = {}
e_time = {}
count1 = 1

#  assignment2.pcap
cwnd_count = {}
cwnd_count = defaultdict(lambda:0,cwnd_count)
cwnd_sizes = defaultdict(list)
seq_list = defaultdict(list)
ack_list = defaultdict(list)
ack_count = 0
for buff in pkt:
    # print buff
    # break
    data = buff[1]
    s_port = int("".join(data[34:36]).encode("hex"),16)
    d_port = int("".join(data[36:38]).encode("hex"),16)
    if int("".join(data[47]).encode("hex")) == 10 or int("".join(data[47]).encode("hex")) == 18 or int("".join(data[47]).encode("hex")) == 11:
        if ack_count > 1:
            if s_port != 80:
                seq_list[s_port].append(int("".join(data[38:42]).encode("hex"),16))
            else:
                ack_list[d_port].append(int("".join(data[42:46]).encode("hex"),16))
                if cwnd_count[d_port] < 10:
                    cwnd_sizes[d_port].append(len(seq_list[d_port]) - len(ack_list[d_port]))
                    cwnd_count[d_port] += 1
        else:
            ack_count += 1
    # print s_port
    source_port.append(s_port)
    if s_port == 80:
        ack_port[(s_port,d_port)].append((int("".join(data[42:46]).encode("hex"),16),buff[0]))
    else:
        sent_port[(s_port,d_port)].append((int("".join(data[38:42]).encode("hex"),16),buff[0]))
    ip = ""
    if int("".join(data[47]).encode("hex")) == 11:
        if e_time.get(d_port) == None:
            e_time[d_port] = buff[0]
    if int("".join(data[47]).encode("hex")) == 2:
        if s_time.get(s_port) == None:
            s_time[s_port] = buff[0]
    for i in xrange(26,30):
        s = "".join(data[i]).encode("hex")
        ip += str(int(s,16)) + "."
    if ip[:-1] == "130.245.145.12":
        # if int("".join(data[47]).encode("hex"),16) == 2 or int("".join(data[47]).encode("hex"),16) == 10:
        # print int("".join(data[34:36]).encode("hex"),16)
        if throughput.get(s_port) == None:
            throughput[s_port] = 0
        throughput[s_port] += (len(data))
        count.append(int("".join(data[34:36]).encode("hex"),16))

    if int("".join(data[47]).encode("hex")) == 2 and scaling_factor.get(s_port) == None:
        scaling_factor[s_port] = 2**int("".join(data[73]).encode("hex"),16)

    # print int("".join(data[47]).encode("hex"))

    if int("".join(data[47]).encode("hex")) == 10 or int("".join(data[47]).encode("hex")) == 18:
        # print "Yes"
        if (s_port,d_port) not in ack_counts or (d_port,s_port) not in ack_counts:
            ack_counts[(s_port,d_port)] = 1
            ack_counts[(d_port,s_port)] = 1
        elif (ack_counts.get((s_port,d_port)) >= 1 and ack_counts.get((s_port,d_port)) < 3) or (ack_counts.get((d_port,s_port)) >= 1 and ack_counts.get((d_port,s_port)) < 3):
            if sd_pairs.get((s_port,d_port)) == None:
                sd_pairs[(s_port,d_port)] = []
            if len(sd_pairs.get((s_port,d_port))) < 2:
                sd_pairs[(s_port,d_port)].append(data)
                # print count1
    count1 += 1
    
total_rtt = {}
total_rtt = defaultdict(lambda: 0,total_rtt)
count = list(set(source_port))
print "\n"
print "\tNumber of TCP flows initiated are : " + str(len(count)-1)
print "\t *************************************"
print "\n"

keys = sd_pairs.keys()

for i in xrange(0,len(keys)):
    for j in xrange(i+1,len(keys)):
        if keys[i][0] == keys[j][1] and keys[i][1] == keys[j][0]:
            # print keys[i],keys[j]
            data1 = sd_pairs.get(keys[i])
            data2 = sd_pairs.get(keys[j])
            for k in xrange(len(data1)):
                print "\t\t\t\t******** Transaction " + str(k + 1) + " ********"
                print "\t\t\tSource Port : " + str(keys[i][0]) + "\t Destination Port : " + str(keys[i][1])
                print "\tSequence Number : " + str(int("".join(data1[k][38:42]).encode("hex"),16)) + "\t Acknowledgement Number : " + str(int("".join(data1[k][42:46]).encode("hex"),16)) + "\t Window Size : " + str(int("".join(data1[k][48:50]).encode("hex"),16)*scaling_factor[keys[i][0]])
                print "\n"
                print "\t\t\tSource Port : " + str(keys[j][0]) + "\t Destination Port : " + str(keys[j][1])
                print "\tSequence Number : " + str(int("".join(data2[k][38:42]).encode("hex"),16)) + "\t Acknowledgement Number : " + str(int("".join(data2[k][42:46]).encode("hex"),16)) + "\t Window Size : " + str(int("".join(data2[k][48:50]).encode("hex"),16)*scaling_factor[keys[i][0]])
                print "\n"

print "\t *********************************** \t"
for key in s_time:
    print "Throughput of : " + str(key) + " is " + str(throughput[key]/(e_time[key] - s_time[key]))

loss_rate = defaultdict(list)
print "\n"
print "\t *********************************** \t"
for key in seq_list:
    print "Loss rate of " + str(key) + " is " + str((len(seq_list[key]) - len(list(set(seq_list[key]))))/float(len(seq_list[key])))

print "\n"
print "\t *********************************** \t"
for key in ack_port.keys():
    print "Average RTT for " + str(key[1]) + " is " + str(compute_rtt(total_rtt,key))

print "\n"
print "\t *********************************** \t"
for key in ack_port.keys():
    error = (len(seq_list[key[1]]) - len(list(set(seq_list[key[1]]))))/float(len(seq_list[key[1]]))
    th_put = (1460 * ((3/2)**0.5))/((error**0.5)*compute_rtt(total_rtt,key))
    print "Theoretical Throughput of " + str(key[1]) + " is " + str(th_put)

print "\n"
print "\t *********************************** \t"
for key in cwnd_sizes:
    print "The first 10 congestion window sizes of " + str(key) + " is " + str(cwnd_sizes[key])

print "\n"
print "\t *********************************** \t"
for key in cwnd_sizes:
    print "The initial congestion window size of " + str(key) + " is " + str(cwnd_sizes[key][0])

print "\n"
print "\t *********************************** \t"
for port in seq_list:
    seq_count = {}
    seq_count = defaultdict(lambda:0,seq_count)
    ack_list_count = {}
    ack_list_count = defaultdict(lambda:0,ack_list_count)
    data_seq = seq_list[port]
    triple_seq = []
    for seq in data_seq:
        seq_count[seq] += 1
        if seq_count[seq] > 1:
            triple_seq.append(seq)
    data_ack = ack_list[port]
    for seq in data_ack:
        ack_list_count[seq] += 1
    triple_count = 0
    timeout_count = 0
    for seq in triple_seq:
        if ack_list_count[seq] >= 3:
            triple_count += 1
        else:
            timeout_count += 1
    print "Triple Duplicate ack for " + str(port) + " is " + str(triple_count)
    print "Retransmission due to time out for " + str(port) + " is " + str(timeout_count)
    print "\n"
    print "\t *********************************** \t"
