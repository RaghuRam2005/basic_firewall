import block
import argparse
import socket
import utils
import log
import monitor
import threading
import time

def command_input_loop(firewall, logs, stop_event):
    """Handle command input in a separate thread"""
    while not stop_event.is_set():
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
                utils.show_blocked(firewall.config)
                    
            elif cmd == "log start":
                if logs.logging_active:
                    print("Logging is already active")
                else:
                    logs.start_logging()
                    print("Logging started successfully")
                
            elif cmd == "log stop":
                if logs.logging_active:
                    logs.stop_logging()
                    print("Logging stopped successfully")
                else:
                    print("Logging is not active")
                
            elif cmd == "exit":
                print("Exiting firewall...")
                if logs.logging_active:
                    logs.stop_logging()
                firewall.save_config()
                stop_event.set()
                break
                
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except Exception as e:
            print(f"Error: {e}")

def interactive_mode(firewall, logs):
    """Run the firewall in interactive mode with improved responsiveness"""
    is_admin = utils.check_admin_privileges()
    
    if not is_admin:
        print("\nWARNING: This script is not running with administrator/root privileges.")
        print("Some features may not work correctly. Consider restarting with elevated privileges.")
        input("Press Enter to continue anyway...")
    
    print("\n--- System Firewall Interactive Mode ---")
    print("Type 'help' for available commands")
    
    # Create an event to signal when to stop
    stop_event = threading.Event()
    
    # Create and start the command input thread
    input_thread = threading.Thread(
        target=command_input_loop,
        args=(firewall, logs, stop_event),
        daemon=True  # This ensures the thread exits when the main program exits
    )
    input_thread.start()
    
    # Main thread keeps the program alive until stop_event is set
    try:
        while not stop_event.is_set():
            time.sleep(0.1)  # Sleep briefly to reduce CPU usage
    except KeyboardInterrupt:
        print("\nReceived keyboard interrupt. Shutting down...")
        if logs.logging_active:
            logs.stop_logging()
        firewall.save_config()
        stop_event.set()
    
    # Wait for the input thread to finish (should be quick since we set the event)
    input_thread.join(timeout=1.0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='System-Level Python Firewall')
    parser.add_argument('--config', help='Path to configuration file', default='firewall_config.json')
    args = parser.parse_args()
    
    # Create components without circular dependencies
    firewall = block.SystemFirewall(config_file=args.config)
    logs = log.ConnectionLogger()
    
    # Create monitor with proper parameters
    network_monitor = monitor.NetworkMonitor(block_callback=firewall.block_ip, logger=logs)
    
    # Connect the components properly
    logs.set_monitor(network_monitor)

    interactive_mode(firewall, logs)
