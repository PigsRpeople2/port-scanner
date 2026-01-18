import requests
import threading
import time
import argparse
from scapy.all import ICMP, IP, sr1, traceroute, TCP, sr
from colorama import init, Fore, Style
from tqdm import tqdm



def scan_ports(target_ip, port_range, max_threads, visual):
    open_ports = []
    
    if isinstance(visual, bool):
        if visual == True:
            if port_range == 65535:
                port_pbar = tqdm(total=65535, desc="Scanning Ports", bar_format="{l_bar}{bar}[{elapsed}<{remaining}][{n_fmt}/{total_fmt}]", leave=True)
            else:
                port_pbar = tqdm(total=(port_range[1] - port_range[0] + 1 if isinstance(port_range, list) else port_range + 1), desc="Scanning Ports", bar_format="{l_bar}{bar}[{elapsed}<{remaining}]", leave=True)
        elif visual == False:
            port_pbar = None
    else:
        port_pbar = visual




    def check_port(port, ):
        try:
            response = requests.get(f"http://{target_ip}:{port}", timeout=1)
            if response.status_code == 200:
                open_ports.append(port)
        except requests.RequestException:
            pass
        
        
        
    threads = []
    
    port_pbar.update(1)
    
    
    if isinstance(port_range, list) and len(port_range) == 2:

        for port in range(port_range[0], port_range[1]):
            while threading.active_count() > max_threads:
                time.sleep(0.01)
            thread = threading.Thread(target=check_port, args=(port, ))
            port_pbar.update(1)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()




    elif isinstance(port_range, int):
        for port in range(1, port_range + 1):
            while threading.active_count() > max_threads:
                time.sleep(0.01)
            thread = threading.Thread(target=check_port, args=(port, ))
            port_pbar.update(1)
            threads.append(thread)
            thread.start()

            
            
        for thread in threads:
            thread.join()


    port_pbar.close()
    return open_ports






def os_scan(target_ip, port_scan, threads, visual):

    if visual == True:
        if port_scan:
            os_pbar = tqdm(total=103, desc="Scanning OS Ports", bar_format="{l_bar}{bar} [{elapsed}<{remaining}]", leave=True)
        else:
            os_pbar = tqdm(total=3, desc="Scanning OS", bar_format="{l_bar}{bar} [{elapsed}<{remaining}]", leave=True)
    elif visual == False:
        os_pbar = None
    else:
        os_pbar = visual

    icmp_packet = IP(dst=target_ip)/ICMP()
    
    response = sr1(icmp_packet, timeout=2, verbose=0)
    if os_pbar:
        os_pbar.update(1)

    result, unanswered = traceroute(target_ip, verbose=0, timeout=2)
    tracedata = result.get_trace()
    if os_pbar:
        os_pbar.update(1)

    est_ttl = len(tracedata) + icmp_packet.ttl - 1
    


    tcp_packet = IP(dst=target_ip)/TCP(dport=80, flags='S')
    est_window = tcp_packet.window
    
    if port_scan:
        open_ports = scan_ports(target_ip, 100, threads, os_pbar) # Raise back to 1000 for actual use
        time.sleep(1)
        if open_ports:
            syn_packet = IP(dst=target_ip)/TCP(dport=open_ports[0], flags='S')
            syn_response = sr1(syn_packet, timeout=2, verbose=0)
        
        rst_port = 1
        if open_ports:
            while open_ports.__contains__(rst_port):
                rst_port =+ 1
    else:
        rst_port = 6545
    rst_packet = IP(dst=target_ip)/TCP(dport=rst_port, flags='R')
    rst_response = sr(rst_packet, timeout=5, verbose=0)
    
    
    #
    # Working on adding loading bar after the ascii art that gets auto updated
    # Remember to make sure that -on and -od disable this feature
    #
    # Also working adding RST and SYN finger printing, might need to change tactic
    # not currently working as its not capturing the rst packet and saying its unanswered
    # rst might not work for some reason so might change to TCP option list + order, looks really annoying to do tho
    #
    # Check chatgpt and work through bottom order as next steps
    #




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
    
    
    
    
    os_pbar.close()
    return {"est_ttl": est_ttl, "est_window": est_window, "os": est_os}
    








parser = argparse.ArgumentParser(description="Basic Port Scanner")
parser.add_argument("target", help="The target IP address to scan.", nargs='?')
parser.add_argument('--port-scan', '-P', action='store_false', help='Enable port scanning, default = True', default=True)
parser.add_argument('--ports', '-p', type=str, help='The range of ports to scan (e.g., "20-80" or "1000"), default = 10000', default="10000")
parser.add_argument('--threads', '-t', type=int, help='Max threads to use, default = 100', default=100)
parser.add_argument('--os-detection', '-o', action='store_true', help='Enable OS detection, default = False', default=False)
parser.add_argument('--os-light', '-ol', action='store_true', help='Enable OS detection without basic port scan that assists with OS detection, used seperate to --os-detection, default = False', default=False)
parser.add_argument('--output-nothing', '-on', action='store_true', help='Disable default output (used during testing)', default=False)
parser.add_argument('--output-data', '-od', action='store_true', help='Output only data and disables visual output', default=False)
parser.add_argument('--all-ports', '-a', action='store_true', help='Scan all 65535 ports (may take a long time)', default=False)

args = parser.parse_args()

run_port_scan = None
open_ports = None
run_os_scan = None
os_details = None

if not args.output_nothing and not args.output_data:
    print(f"{Fore.GREEN} ███████████                      █████        █████████                                                             ")
    print(f"{Fore.GREEN}▒▒███▒▒▒▒▒███                    ▒▒███        ███▒▒▒▒▒███                                                            ")
    print(f"{Fore.GREEN} ▒███    ▒███  ██████  ████████  ███████     ▒███    ▒▒▒   ██████   ██████   ████████   ████████    ██████  ████████ ")
    print(f"{Fore.GREEN} ▒██████████  ███▒▒███▒▒███▒▒███▒▒▒███▒      ▒▒█████████  ███▒▒███ ▒▒▒▒▒███ ▒▒███▒▒███ ▒▒███▒▒███  ███▒▒███▒▒███▒▒███")
    print(f"{Fore.GREEN} ▒███▒▒▒▒▒▒  ▒███ ▒███ ▒███ ▒▒▒   ▒███        ▒▒▒▒▒▒▒▒███▒███ ▒▒▒   ███████  ▒███ ▒███  ▒███ ▒███ ▒███████  ▒███ ▒▒▒ ")
    print(f"{Fore.GREEN} ▒███        ▒███ ▒███ ▒███       ▒███ ███    ███    ▒███▒███  ███ ███▒▒███  ▒███ ▒███  ▒███ ▒███ ▒███▒▒▒   ▒███     ")
    print(f"{Fore.GREEN} █████       ▒▒██████  █████      ▒▒█████    ▒▒█████████ ▒▒██████ ▒▒████████ ████ █████ ████ █████▒▒██████  █████    ")
    print(f"{Fore.GREEN}▒▒▒▒▒         ▒▒▒▒▒▒  ▒▒▒▒▒        ▒▒▒▒▒      ▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒  ▒▒▒▒▒▒  ▒▒▒▒▒     ")
    print(f"{Style.RESET_ALL} ")

visual = True

if args.target:
    if args.output_nothing or args.output_data:
            visual = False

    if args.os_detection:
        os_details = os_scan(args.target, True, args.threads, visual)
        run_os_scan = True

    if args.os_light and not args.os_detection:
        os_details = os_scan(args.target, False, 0)
        run_os_scan = True

    if args.port_scan:
        if args.all_ports:
            port_range = 65535
        elif '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
            port_range = [start_port, end_port]
            print(port_range[1])
            print(port_range[0])
        else:
            port_range = int(args.ports)

        

        open_ports = scan_ports(args.target, port_range, args.threads, visual)
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
    

if not args.output_nothing:
    if args.output_data:
        if run_port_scan:
            if open_ports:
                print(f"{open_ports}")
            else:
                print("None")

        if run_os_scan:
            if os_details:
                print(f"{os_details['est_ttl']}")
                print(f"{os_details['est_window']}")
                print(f"{os_details['os']}")
    else:
        
        

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



