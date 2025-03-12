import ctypes
import platform
import os
import json

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
    print("Blocked sites")
    for site in config["blocked_sites"]:
        print(f"{site}")

def load_config(config, config_file):
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                loaded_config = json.load(f)
                config.update(loaded_config)
            print(f"Configuretion loaded from {config_file}")
            return config
        except Exception as e:
            print(f"Error while loading configuration: {e}")
            return config
    else:
        print(f"No configuration file found at {config_file}")
        return save_config(config, config_file)

def save_config(config, config_file):
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"Configuration saved to {config_file}")
        return config
    except Exception as e:
        print(f"Error saving configuration: {e}")
        return config
    

