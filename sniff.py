# Import the Scapy library
from scapy.all import *

# Define the function to be called for each packet captured
def packet_callback(packet):
    # Print the packet's information to the console
    print(packet.show())
    # Save the packet to a .cap file
    wrpcap("captured_packets.cap", packet, append=True)

# Start the sniffer, filtering for TCP packets only
sniff(filter="tcp", prn=packet_callback, store=0)
