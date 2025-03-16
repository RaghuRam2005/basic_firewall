# Basic Firewall Implemented in Python

This program implements a simple firewall system that can monitor network traffic and detect anomalies. It can block IP addresses if the request rate is too high and restrict access to malicious sites. The firewall features a simple command-line interface for ease of use.

## Features
- **Block and Unblock IP Addresses**: Prevent connections from or to specified IPs.
- **Block and Unblock Websites**: Restrict access to specific domains.
- **Logging**: Monitor network activity and save logs in a CSV file.
- **Persistent Rules**: Blocked IPs and sites remain restricted even after the program stops.

## Commands

### Block an IP Address
Blocks connections from or to the specified IP address.
```bash
block ip <ip_address>
```

### Unblock an IP Address
Removes a previously blocked IP address from the firewall.
```bash
unblock ip <ip_address>
```

### Block a Website
Restricts access to a specific website.
```bash
block site <website_url>
```
Example:
```bash
block site https://github.com/
```

### Unblock a Website
Removes a website from the blocked list.
```bash
unblock site <website_url>
```
Example:
```bash
unblock site https://github.com/
```

### Apply Firewall Rules
Applies all the blocking/unblocking rules set in the session.
```bash
apply
```

### Show Blocked IPs and Websites
Displays a list of currently blocked IPs and websites.
```bash
show blocked
```

### Start Logging Network Activity
Begins monitoring network activity and logs connection attempts.
```bash
log start
```

### Stop Logging Network Activity
Stops monitoring and saves the log data to a CSV file.
```bash
log stop
```

### Display Help Menu
Lists all available commands and their usage.
```bash
help
```

### Exit the Program
Terminates the firewall application.
```bash
exit
```

## Important Notes
- **Windows Only**: This firewall is designed to work on Windows.
- **Persistent Blocking**: Blocked IPs and websites remain blocked even after exiting the program. To remove restrictions, use the unblock command or manually update Windows Firewall settings.
- **Administrative Privileges Required**: Running this program requires administrator permissions.

## Installation & Usage
Ensure you have Python installed and run the script with administrator rights:
```bash
python firewall.py
```

For best performance, run the program in a terminal with elevated privileges.

---
### Disclaimer
This tool is for educational and security research purposes only. Use it responsibly and in accordance with local laws and regulations.

