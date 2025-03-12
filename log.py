import csv
import datetime
import monitering

class ConnectionLogger:
    def __init__(self):
        self.logs = []
        self.logging_active = False

    def log_connection(self, src_ip, dst_ip, dst_port, action):
        try:
            file_name = f"log_{datetime.datetime.now().isoformat().replace(':', '-')}.csv"
            with open(file_name, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
                writer.writerow([datetime.datetime.now().isoformat(), src_ip, dst_ip, dst_port, action])
        except Exception as e:
            print(f"Exception occured while logging connection. {e}")
    
    def start_logging(self):
        self.logging_active = True
        print(f"stared logging from {datetime.datetime.now()}")

        moniter = monitering.NetstatMonitor()
        moniter.start_packet_sniffing()

    


    