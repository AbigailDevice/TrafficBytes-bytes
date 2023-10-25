from collections import deque
import time
from psutil import net_io_counters
from scapy.all import sniff, IP, TCP, UDP

# Listen for network packets
def network_packet_listener(interface, maxlen=100):
    packet_buffer = deque(maxlen=maxlen)

    def packet_handler(packet):
        packet_buffer.append(packet)

    sniff(iface=interface, prn=packet_handler)

    return packet_buffer

def monitor_network_traffic(interface, interval=1):
    start_time = time.time()
    prev_bytes_sent = prev_bytes_recv = 0

    while True:
        current_time = time.time()
        elapsed_time = current_time - start_time
        start_time = current_time

        # Get current network traffic information
        bytes_sent, bytes_recv = net_io_counters(pernic=True)[interface]

        # Calculate the bytes sent and received per second
        bytes_sent_s = (bytes_sent - prev_bytes_sent) / elapsed_time
        bytes_recv_s = (bytes_recv - prev_bytes_recv) / elapsed_time

        # Update previous bytes sent and received
        prev_bytes_sent, prev_bytes_recv = bytes_sent, bytes_recv

        print(f"Bytes Sent per Second: {bytes_sent_s} bytes")
        print(f"Bytes Received per Second: {bytes_recv_s} bytes")

        time.sleep(interval)

# Usage: 
# monitor_network_traffic('en0')
