import requests
import threading
import time
import argparse
from scapy.all import ICMP, IP, sr1, traceroute, TCP, sr


def os_scan(target_ip):
    icmp_packet = IP(dst=target_ip)/ICMP()
    
    response = sr1(icmp_packet, timeout=2, verbose=0)
    
    result, unanswered = traceroute(target_ip, verbose=0, timeout=2)
    tracedata = result.get_trace()
    
    est_ttl = len(tracedata) + icmp_packet.ttl - 1
    


    tcp_packet = IP(dst=target_ip)/TCP(dport=80, flags='S')
    est_window = tcp_packet.window
    
    est_os = "Unknown"
    if est_ttl <= 64:
        if est_window == 5840 or est_window == 5720:
            est_os = "Linux (Kernel 2.4/2.6/customized)"
        elif est_window == 65535:
            est_os = "FreeBSD/OpenBSD/NetBSD"
    elif 65 <= est_ttl <= 128:
        if est_window == 65535:
            est_os = "Windows XP/8/10/Server 2003+"
        elif est_window == 8192:
            est_os = "Windows 7/Vista"
    elif 129 <= est_ttl <= 255:
        if est_window == 4128:
            est_os = "Cisco Router (IOS 12.4+)"
        elif est_window == 8760:
            est_os = "Solaris 10/11"
    
    
    
    
    
    return {"est_ttl": est_ttl, "est_window": est_window, "os": est_os}
    





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
parser.add_argument('--os-detection', '-o', action='store_true', help='Enable OS detection, default = False', default=False)
parser.add_argument('--port-scan', '-P', action='store_false', help='Enable port scanning, default = True', default=True)



args = parser.parse_args()

run_port_scan = None
open_ports = None
run_os_scan = None
os_details = None

if args.target:

    if args.os_detection:
        os_details = os_scan(args.target)
        run_os_scan = True

    if args.port_scan:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
            port_range = [start_port, end_port]
        else:
            port_range = int(args.ports)

        open_ports = scan_ports(args.target, port_range, args.threads)
        run_port_scan = True

        
        
        
if not args.target:
    target = input("Target IP address: ")
    port_scan = input("Enable port scanning? (y/n, default y): ")
    
    port_start = None
    port_end = None
    threads = None
    if port_scan.lower() != 'n':
        port_start = input("Starting port (default 1): ")
        port_end = input("Ending port (default 10000): ")
        threads = input("Max threads (default 100): ")
        if not threads:
            threads = 100
        
        if not port_start:
            port_start = 1
        
        if not port_end:
            port_end = 10000
    
    
    os_detection = input("Enable OS detection? (y/n, default n): ")
    
    
    
    if os_detection.lower() == 'y':
        os_details = os_scan(target)
        run_os_scan = True
        
    if port_scan.lower() != 'n':
        open_ports = scan_ports(target, [int(port_start), int(port_end)], int(threads))
        run_port_scan = True
    
    
if run_port_scan:
    if open_ports:
        print(f"Open ports: {open_ports}")
    else:
        print("No open ports found.")

if run_os_scan:
    if os_details:
        print(f"Initial TTL: {os_details['est_ttl']}")
        print(f"Window Size: {os_details['est_window']}")
        print(f"Estimated OS: {os_details['os']}")
    