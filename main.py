import blocking
import argparse
import socket
import utils
import logging

def interactive_mode(firewall):
    """Run the firewall in interactive mode"""
    is_admin = utils.check_admin_privileges()
    
    if not is_admin:
        print("\nWARNING: This script is not running with administrator/root privileges.")
        print("Some features may not work correctly. Consider restarting with elevated privileges.")
        input("Press Enter to continue anyway...")
    
    print("\n--- System Firewall Interactive Mode ---")
    print("Type 'help' for available commands")

    load = logging.connectionlogger
    
    while True:
        try:
            cmd = input("\nfirewall> ").strip().lower()
            
            if cmd == "help":
                utils.print_help()
                
            elif cmd == "apply":
                firewall.apply_all_rules()
                    
            elif cmd.startswith("block ip "):
                ip = cmd[9:].strip()
                try:
                    # Validate IP
                    socket.inet_aton(ip)
                    firewall.block_ip(ip)
                except socket.error:
                    print(f"Invalid IP address: {ip}")
                    
            elif cmd.startswith("unblock ip "):
                ip = cmd[11:].strip()
                firewall.unblock_ip(ip)
                
            elif cmd.startswith("block site "):
                site = cmd[11:].strip()
                firewall.block_site(site)
                
            elif cmd.startswith("unblock site "):
                site = cmd[13:].strip()
                firewall.unblock_site(site)
                
            elif cmd == "show blocked":
                utils.show_blocked()
                    
            elif cmd == "log start":
                firewall.start_logging()
                
            elif cmd == "log stop":
                firewall.stop_logging()
                
            elif cmd == "exit":
                print("Exiting firewall...")
                if firewall.logging_active:
                    firewall.stop_logging()
                firewall.save_config()
                break
                
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='System-Level Python Firewall')
    parser.add_argument('--config', help='Path to configuration file', default='firewall_config.json')
    args = parser.parse_args()
    
    firewall = blocking.SystemFirewall(config_file=args.config)
    interactive_mode(firewall)
    