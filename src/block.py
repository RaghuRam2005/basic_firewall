import socket
import threading
import time
import json
import os
import signal
import sys
from collections import defaultdict
import subprocess
import platform

base_path = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(base_path, "..", "/config")

class SystemFirewall:
    """
    managing and blocking IP's based on request from user
    """
    def __init__(self, config_file="firewall_config.json"):
        # Default configuration
        self.config = {
            "blocked_ips": [],
            "blocked_sites": [],
            "rate_limit": 30,  # Max requests per minute
            "rate_window": 60,  # Time window in seconds
            "log_file": "firewall_logs.json"
        }
        self.config_file = config_file
        self.os_type = platform.system()  # 'Windows', 'Linux', or 'Darwin' (macOS)
        self.load_config()
        # Connection tracking
        self.connections = defaultdict(list)
        self.connection_lock = threading.Lock()
        # Logging
        self.logs = []
        self.logging_active = False
        self.logging_start_time = None
        self.logging_end_time = None
        # DNS cache for hostname resolution
        self.dns_cache = {}
        self.dns_cache_lock = threading.Lock()
        # Signal handling for clean shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        print(f"Firewall initialized with {len(self.config['blocked_ips'])} \
              blocked IPs and {len(self.config['blocked_sites'])} blocked sites")
        print(f"Detected operating system: {self.os_type}")
        
    def load_config(self):
        """Load firewall configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    self.config.update(loaded_config)
                print(f"Configuration loaded from {self.config_file}")
            except Exception as e:
                print(f"Error loading configuration: {e}")
        else:
            print(f"No configuration file found at {self.config_file}, using defaults")
            self.save_config()
    
    def save_config(self):
        """Save current firewall configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"Error saving configuration: {e}")
    
    def is_ip_blocked(self, ip):
        """Check if an IP is in the blocked list"""
        return ip in self.config["blocked_ips"]
    
    def is_site_blocked(self, hostname):
        """Check if a site is in the blocked list"""
        hostname = hostname.lower()
        # Strip http:// or https:// if present
        if hostname.startswith("http://"):
            hostname = hostname[7:]
        elif hostname.startswith("https://"):
            hostname = hostname[8:]
        # Strip www. if present
        if hostname.startswith("www."):
            hostname = hostname[4:]
        # Strip path if present
        hostname = hostname.split("/")[0]
        for blocked_site in self.config["blocked_sites"]:
            blocked_site = blocked_site.lower()
            # Exact match
            if hostname == blocked_site:
                return True
            # Check if this is a subdomain of a blocked domain
            if hostname.endswith("." + blocked_site):
                return True
        return False
    
    def check_rate_limit(self, ip):
        """Check if an IP has exceeded the rate limit"""
        with self.connection_lock:
            # Clean old requests
            current_time = time.time()
            time_threshold = current_time - self.config["rate_window"]
            # Keep only recent requests
            self.connections[ip] = [t for t in self.connections[ip] if t > time_threshold]
            # Check if over threshold
            if len(self.connections[ip]) >= self.config["rate_limit"]:
                print(f"Rate limit exceeded for IP {ip}, blocking")
                self.block_ip(ip)
                return True
            # Add current request timestamp
            self.connections[ip].append(current_time)
            return False
    
    def block_ip(self, ip):
        """Add an IP to the blocked list and apply system firewall rules"""
        if ip not in self.config["blocked_ips"]:
            self.config["blocked_ips"].append(ip)
            self.save_config()
            self.apply_ip_block(ip)
            print(f"IP {ip} has been blocked")
    
    def unblock_ip(self, ip):
        """Remove an IP from the blocked list and update system firewall rules"""
        if ip in self.config["blocked_ips"]:
            self.config["blocked_ips"].remove(ip)
            self.save_config()
            self.remove_ip_block(ip)
            print(f"IP {ip} has been unblocked")
    
    def block_site(self, hostname):
        """Add a site to the blocked list and apply system firewall rules"""
        hostname = hostname.lower()
        # Strip http:// or https:// if present
        if hostname.startswith("http://"):
            hostname = hostname[7:]
        elif hostname.startswith("https://"):
            hostname = hostname[8:]
        # Strip www. if present
        if hostname.startswith("www."):
            hostname = hostname[4:]
        # Strip path if present
        hostname = hostname.split("/")[0]
        if hostname not in self.config["blocked_sites"]:
            self.config["blocked_sites"].append(hostname)
            self.save_config()
            self.apply_site_block(hostname)
            print(f"Site {hostname} has been blocked")
    
    def unblock_site(self, hostname):
        """Remove a site from the blocked list and update system firewall rules"""
        hostname = hostname.lower()
        # Strip http:// or https:// if present
        if hostname.startswith("http://"):
            hostname = hostname[7:]
        elif hostname.startswith("https://"):
            hostname = hostname[8:]
        # Strip www. if present
        if hostname.startswith("www."):
            hostname = hostname[4:]
        # Strip path if present
        hostname = hostname.split("/")[0]
        if hostname in self.config["blocked_sites"]:
            self.config["blocked_sites"].remove(hostname)
            self.save_config()
            self.remove_site_block(hostname)
            print(f"Site {hostname} has been unblocked")
    
    def resolve_hostname(self, hostname):
        """Resolve hostname to IP address with caching"""
        with self.dns_cache_lock:
            if hostname in self.dns_cache:
                return self.dns_cache[hostname]
            try:
                ip_addresses = []
                # Try to get all IPs for the hostname
                info = socket.getaddrinfo(hostname, None)
                for item in info:
                    ip = item[4][0]
                    if ip not in ip_addresses:
                        ip_addresses.append(ip)
                if ip_addresses:
                    self.dns_cache[hostname] = ip_addresses
                    return ip_addresses
            except socket.gaierror:
                pass
            return []
    
    def apply_ip_block(self, ip):
        """Apply IP blocking rule to system firewall"""
        if self.os_type == "Windows":
            # Windows Firewall
            try:
                rule_name = f"BlockIP_{ip.replace('.', '_')}"
                # Check if rule already exists
                check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
                result = subprocess.run(check_cmd, shell=True, stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE)
                if "No rules match the specified criteria" in result.stdout.decode():
                    # Create inbound rule
                    cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}" \
                    dir=in action=block remoteip={ip}'
                    # Create outbound rule
                    cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_out" \
                    dir=out action=block remoteip={ip}'
                    subprocess.run(cmd_in, shell=True, check=True)
                    subprocess.run(cmd_out, shell=True, check=True)
                    print(f"Windows Firewall rules added for IP {ip}")
            except subprocess.CalledProcessError as e:
                print(f"Error applying Windows Firewall rule: {e}")
        else:
            print(f"Unsporrted operating system {self.os_type}")
    
    def remove_ip_block(self, ip):
        """Remove IP blocking rule from system firewall"""
        if self.os_type == "Windows":
            # Windows Firewall
            try:
                rule_name = f"BlockIP_{ip.replace('.', '_')}"
                # Remove inbound rule
                cmd_in = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                # Remove outbound rule
                cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name}_out"'
                
                subprocess.run(cmd_in, shell=True, check=True)
                subprocess.run(cmd_out, shell=True, check=True)
                print(f"Windows Firewall rules removed for IP {ip}")
            except subprocess.CalledProcessError as e:
                print(f"Error removing Windows Firewall rule: {e}")
        else:
            print(f"Unsupported operating system: {self.os_type}")
    
    def apply_site_block(self, hostname):
        """Resolve hostname to IP and apply block rules"""
        ip_addresses = self.resolve_hostname(hostname)
        if ip_addresses:
            print(f"Resolved {hostname} to {', '.join(ip_addresses)}")
            for ip in ip_addresses:
                if ip not in self.config["blocked_ips"]:  # Avoid duplicate blocks
                    self.apply_ip_block(ip)
        else:
            print(f"Could not resolve {hostname} to an IP address")
            # Add the site to hosts file on Windows
            if self.os_type == "Windows":
                try:
                    hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
                    hosts_entry = f"127.0.0.1 {hostname} www.{hostname}"
                    # Check if entry already exists
                    with open(hosts_file, 'r') as f:
                        content = f.read()
                    if hostname not in content:
                        try:
                            with open(hosts_file, 'a') as f:
                                f.write(f"\n{hosts_entry}\n")
                            print(f"Added {hostname} to {hosts_file}")
                        except PermissionError:
                            print(f"Need administrator privileges to modify {hosts_file}")
                            print(f"Manually add this line to {hosts_file}:")
                            print(hosts_entry)
                except Exception as e:
                    print(f"Error modifying hosts file: {e}")
            else:
                print(f"Unsupported operating system {self.os_type}")
    
    def remove_site_block(self, hostname):
        """Remove site blocking rules"""
        ip_addresses = self.resolve_hostname(hostname)
        if ip_addresses:
            print(f"Resolved {hostname} to {', '.join(ip_addresses)}")
            for ip in ip_addresses:
                # Only remove if not explicitly blocked
                if ip not in self.config["blocked_ips"]:
                    self.remove_ip_block(ip)
        # Remove from hosts file if present
        hosts_file = "/etc/hosts" if self.os_type in ["Linux", "Darwin"] \
        else r"C:\Windows\System32\drivers\etc\hosts"
        if os.path.exists(hosts_file):
            try:
                with open(hosts_file, 'r') as f:
                    lines = f.readlines()
                # Filter out lines with this hostname
                new_lines = [line for line in lines if hostname not in line]
                if len(new_lines) != len(lines):
                    try:
                        with open(hosts_file, 'w') as f:
                            f.writelines(new_lines)
                        print(f"Removed {hostname} from {hosts_file}")
                    except PermissionError:
                        print(f"Need privileges to modify {hosts_file}")
                        print(f"Manually remove lines containing {hostname} from {hosts_file}")
            except Exception as e:
                print(f"Error modifying hosts file: {e}")
    

    def apply_all_rules(self):
        """Apply all configured rules to the system firewall"""
        print("Applying all configured firewall rules...")
        # Apply IP blocks
        for ip in self.config["blocked_ips"]:
            self.apply_ip_block(ip)
        # Apply site blocks
        for site in self.config["blocked_sites"]:
            self.apply_site_block(site)
        print("All rules applied.")
    
    def handle_shutdown(self):
        """Handle graceful shutdown"""
        print("\nShutting down firewall...")
        if self.logging_active:
            self.stop_logging()
        self.save_config()
        sys.exit(0)
