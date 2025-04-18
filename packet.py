import scapy.all as scapy

# This function will analyze and display the captured packet
def packet_callback(packet):
    print("\nPacket captured:")
    
    # Check if the packet has an IP layer
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src  # Source IP address
        ip_dst = packet[scapy.IP].dst  # Destination IP address
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
    
    # Check if the packet has a transport layer (TCP/UDP)
    if packet.haslayer(scapy.TCP):
        print(f"Protocol: TCP")
        print(f"Source Port: {packet.sport}")
        print(f"Destination Port: {packet.dport}")
    elif packet.haslayer(scapy.UDP):
        print(f"Protocol: UDP")
        print(f"Source Port: {packet.sport}")
        print(f"Destination Port: {packet.dport}")
    
    # Display the payload data (if any)
    if packet.haslayer(scapy.Raw):
        print("Payload Data:")
        print(packet[scapy.Raw].load)

# Start sniffing packets on the network
def start_sniffing(interface="eth0"):
    print(f"Starting packet sniffing on interface {interface}...")
    scapy.sniff(iface=interface, prn=packet_callback, store=False)

# Run the sniffer (change "eth0" to your active network interface)
if __name__ == "__main__":
    start_sniffing("eth0")
