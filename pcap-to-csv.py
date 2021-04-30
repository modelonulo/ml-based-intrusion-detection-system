from scapy.all import *
from scapy.layers.inet import IP, TCP
import csv
 
count = 0
total_length = 0 
 
 
# script example to obtein some variables from pcap files 
with PcapReader('/home/Disciplinas/OficinaMaker/PAD/Wednesday-WorkingHours.pcap') as packets:
    with open('WWH.csv', 'w', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['timestamp', 'source_ip', 'destination_ip', 'source_port', 'destination_port', 'total_length', 'ip_version', 'ip_ihl', 'ip_tos', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_proto', 'ip_chksum', 'tcp_seq', 'tcp_ack', 'tcp_dataofs', 'tcp_reserved', 'tcp_flags', 'tcp_window', 'tcp_chksum', 'tcp_urgptr', 'tcp_options'])
        for packet in packets:
            count+=1
            if (count%1000 == 0):
                print(count, datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f'))
            if TCP in packet:
                #packet.show()
                timestamp = packet.time #not 
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
                total_length += packet[IP].len
                ip_version = packet[IP].version
                ip_ihl = packet[IP].ihl
                ip_tos = packet[IP].tos
                ip_len = packet[IP].len
                ip_id = packet[IP].id
                ip_flags = packet[IP].flags
                ip_frag = packet[IP].frag
                ip_ttl = packet[IP].ttl
                ip_proto = packet[IP].proto
                ip_chksum = packet[IP].chksum
                tcp_seq = packet[TCP].seq
                tcp_ack = packet[TCP].ack
                tcp_dataofs = packet[TCP].dataofs
                tcp_reserved = packet[TCP].reserved
                tcp_flags = packet[TCP].flags
                tcp_window = packet[TCP].window
                tcp_chksum = packet[TCP].chksum
                tcp_urgptr = packet[TCP].urgptr
                tcp_options = packet[TCP].options
 
 
                writer.writerow([timestamp, source_ip, destination_ip, source_port, destination_port, total_length, ip_version, ip_ihl, ip_tos, ip_len, ip_id, ip_flags, ip_frag, ip_ttl, ip_proto, ip_chksum, tcp_seq, tcp_ack, tcp_dataofs, tcp_reserved, tcp_flags, tcp_window, tcp_chksum, tcp_urgptr, tcp_options])
print('end')
