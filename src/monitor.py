from scapy.sendrecv import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
import threading
import time

class NetworkMonitor:
    def __init__(self, block_callback=None, logger=None):
        self.request_count = {}
        self.request_time_limit = 60  # 1 minute window
        self.request_count_limit = 20  # Max 20 requests/minute
        self.sniffer = None
        self._stop_event = threading.Event()
        self.block_callback = block_callback  # Callback to block IPs
        self.lock = threading.Lock()  # For thread-safe operations
        self.blocked_ips = set()  # Track recently blocked IPs
        self.block_cooldown = 300  # 5 minutes cooldown before re-blocking
        self.logger = logger  # Accept logger as an argument instead of creating it
        
        # Throttle the number of block messages
        self.last_block_message_time = 0
        self.blocks_since_last_message = 0

    def start_monitoring(self):
        """Start monitoring network traffic in a background thread"""
        if not self.sniffer:
            self._stop_event.clear()
            self.sniffer = AsyncSniffer(
                prn=self.process_packet,
                stop_filter=lambda _: self._stop_event.is_set()
            )
            self.sniffer.start()
            print("Network monitoring started")

    def stop_monitoring(self):
        """Stop monitoring network traffic"""
        if self.sniffer:
            self._stop_event.set()
            self.sniffer.join(timeout=2.0)  # Wait up to 2 seconds for it to stop
            self.sniffer = None
            print("Network monitoring stopped")

    def process_packet(self, packet):
        """Process individual network packets"""
        if not packet.haslayer(IP):
            return
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        dst_port = None
        self._update_request_count(src_ip)
        details = ""

        # Analyze transport layer
        if packet.haslayer(TCP):
            transport_layer = packet[TCP]
            dst_port = transport_layer.dport
            details = f"TCP port {dst_port}"
        elif packet.haslayer(UDP):
            transport_layer = packet[UDP]
            dst_port = transport_layer.dport
            details = f"UDP port {dst_port}"

        # Analyze DNS layer
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            try:
                if dns_layer.qr == 0:  # DNS Query
                    if dns_layer.qd:
                        qname = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                        details = f"DNS Query: {qname}"
                else:  # DNS Response
                    if dns_layer.an:
                        answer = dns_layer.an[0]
                        if answer.type == 1:  # A record
                            details = f"DNS Response: {answer.rdata}"
            except Exception as e:
                details = f"DNS Error: {str(e)}"

        # Log connection if enabled
        if self.logger and hasattr(self.logger, 'is_logging') and self.logger.is_logging:
            self.logger.log_connection(src_ip, dst_ip, dst_port, details)
    
    def _update_request_count(self, ip):
        """Track request counts and trigger blocking if needed"""
        with self.lock:
            current_time = time.time()
            
            # Initialize or update count
            if ip not in self.request_count:
                self.request_count[ip] = {
                    'count': 1,
                    'start_time': current_time,
                    'last_blocked': 0
                }
            else:
                # Reset if window expired
                if current_time - self.request_count[ip]['start_time'] > self.request_time_limit:
                    self.request_count[ip] = {
                        'count': 1,
                        'start_time': current_time,
                        'last_blocked': self.request_count[ip]['last_blocked']
                    }
                else:
                    self.request_count[ip]['count'] += 1

            # Check if should block
            if (self.request_count[ip]['count'] > self.request_count_limit and 
                current_time - self.request_count[ip]['last_blocked'] > self.block_cooldown):
                
                # Throttle messages to avoid flooding console
                if current_time - self.last_block_message_time > 5:  # Only print every 5 seconds
                    if self.blocks_since_last_message > 0:
                        print(f"Blocked {self.blocks_since_last_message} additional IPs in the last 5 seconds")
                    print(f"Blocking {ip} for exceeding rate limit")
                    self.last_block_message_time = current_time
                    self.blocks_since_last_message = 0
                else:
                    self.blocks_since_last_message += 1
                
                self.request_count[ip]['last_blocked'] = current_time
                
                # Call block callback if available
                if self.block_callback:
                    try:
                        self.block_callback(ip)
                    except Exception as e:
                        print(f"Error blocking IP {ip}: {e}")
        