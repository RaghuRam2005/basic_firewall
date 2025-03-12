import scapy.all as scapy
import socket
import platform
import log

class NetstatMonitor:
    def __init__(self, logging_active=True):
        if platform.system() != "Windows":
            raise OSError("This script is only compatible with Windows.")
        self.logging_active = logging_active

    def start_packet_sniffing(self):
        """Start monitoring network connections using Scapy"""
        def packet_callback(packet):
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
                src_ip = packet[scapy.IP].src
                dest_ip = packet[scapy.IP].dst
                dest_port = packet[scapy.TCP].dport
                
                # Resolve hostname if possible
                dest_host = dest_ip
                try:
                    dest_host = socket.gethostbyaddr(dest_ip)[0]
                except socket.herror:
                    pass
                
                action = "ALLOWED"
                if self.is_ip_blocked(dest_ip) or self.is_site_blocked(dest_host):
                    action = "BLOCKED"

                # Need to update the implementation

                log.ConnectionLogger.log_connection(src_ip, dest_host, dest_port, action)
        
        print("Starting packet sniffing...")
        scapy.sniff(filter="tcp", prn=packet_callback, store=False)
    
    def is_ip_blocked(self, ip):
        """Check if an IP is blocked (Placeholder implementation)"""
        return False
    
    def is_site_blocked(self, site):
        """Check if a site is blocked (Placeholder implementation)"""
        return False

