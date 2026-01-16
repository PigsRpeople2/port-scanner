import requests
import threading
import time
import argparse



def scan_ports(target_ip, port_range, max_threads):
    open_ports = []
    
    def check_port(port):
        try:
            response = requests.get(f"http://{target_ip}:{port}", timeout=1)
            if response.status_code == 200:
                open_ports.append(port)
        except requests.RequestException:
            pass
        
        
        
    threads = []
    
    
    
    
    if isinstance(port_range, list) and len(port_range) == 2:
        for port in range(port_range[0], port_range[1] + 1):
            while threading.active_count() > max_threads:
                time.sleep(0.01)
            thread = threading.Thread(target=check_port, args=(port,))
            threads.append(thread)
            thread.start()


        for thread in threads:
            thread.join()




    if isinstance(port_range, int):
        for port in range(1, port_range + 1):
            while threading.active_count() > max_threads:
                time.sleep(0.01)
            thread = threading.Thread(target=check_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            
        for thread in threads:
            thread.join()



    return open_ports




parser = argparse.ArgumentParser(description="Basic Port Scanner")
parser.add_argument("target", help="The target IP address to scan.", nargs='?')
parser.add_argument('--ports', '-p', type=str, help='The range of ports to scan (e.g., "20-80" or "1000"), default = 10000', default="10000")
parser.add_argument('--threads', '-t', type=int, help='Max threads to use, default = 100', default=100)



args = parser.parse_args()

if '-' in args.ports:
    start_port, end_port = map(int, args.ports.split('-'))
    port_range = [start_port, end_port]
else:
    port_range = int(args.ports)


if not args.target:
    print("Error: Target IP address is required.")
    exit(1)


open_ports = scan_ports(args.target, port_range, args.threads)

if open_ports:
    print(f"Open ports: {open_ports}")
else:
    print("No open ports found.")