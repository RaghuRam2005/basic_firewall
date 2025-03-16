import ctypes
import platform
import os

def check_admin_privileges():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
            return False
    else:
        return os.geteuid() == 0
    

def print_help():
        print("Available commands:")
        print("  apply - Apply all configured rules to system firewall")
        print("  block ip <ip> - Block an IP address")
        print("  unblock ip <ip> - Unblock an IP address")
        print("  block site <hostname> - Block a website")
        print("  unblock site <hostname> - Unblock a website")
        print("  show blocked - Show all blocked IPs and sites")
        print("  log start - Start logging connections")
        print("  log stop - Stop logging and save logs")
        print("  exit - Exit the firewall")

def show_blocked(config):
    print("Blocked IPs: ")
    for ip in config["blocked_ips"]:
        print(f"{ip}")
    print("Blocked sites: ")
    for site in config["blocked_sites"]:
        print(f"{site}")
