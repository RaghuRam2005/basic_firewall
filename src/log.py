import csv
import datetime
import os

base_path = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(base_path, "..", "/logs")

class ConnectionLogger:
    def __init__(self):
        self.logs = []
        self.logging_active = False
        self.is_logging = False
        self.monitor = None  # Will be set from outside
        self.file_name = path

    def set_monitor(self, monitor):
        """Set the monitor reference without creating a circular dependency"""
        self.monitor = monitor

    def start_logging(self):
        self.logging_active = True
        self.is_logging = True
        print(f"Started logging from {datetime.datetime.now()}")
        if self.monitor:
            self.monitor.start_monitoring()

    def stop_logging(self):
        if self.logging_active:
            self.logging_active = False
            self.is_logging = False
        if self.monitor:
            self.monitor.stop_monitoring()

    def log_connection(self, src_ip, dst_ip, dst_port, action):
        try:
            if not hasattr(self, 'file_name') or not self.file_name:
                self.file_name = "connection_logs.csv"
                
            with open(self.file_name, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
                writer.writerow([datetime.datetime.now().isoformat(), src_ip, dst_ip, dst_port, action])
        except Exception as e:
            print(f"Exception occurred while logging connection. {e}")
