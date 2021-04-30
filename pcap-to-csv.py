from scapy.all import *
from scapy.layers.inet import IP, TCP
import csv

count = 0

# example to open one of the datasets in .pcap format and extrat some variables
with PcapReader('/home/camila/ml-ids/Wednesday-WorkingHours.pcap') as packets:
    with open('WWH.csv', 'w', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['timestamp', 'source_ip', 'destination_ip', 'source_port', 'destination_port'])
        for packet in packets:
            count+=1
            if (count%1000 == 0):
                print(count, datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f'))
            if TCP in packet:
                timestamp = packet.time
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
                writer.writerow([timestamp, source_ip, destination_ip, source_port, destination_port])
print('END')
