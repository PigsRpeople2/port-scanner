Basic Port Scanner


Flags:

    --help, -h              Show help message and exit

    --port-scan -P          Toggle port scanning, default true
    
    --ports, -p PORTS       The range of ports to scan (e.g., "20-80" or "1000"), default = 10000
  
    --threads, -t THREADS   Max threads to use, default = 100

    --os-detection, -o      Enable OS detection, default = False
    
    --os-light, -ol         Enable OS detection without basic port scan, used seperate to -o, default = False 

    --output-nothing, -on   Disable default output (used during testing)

    --output-data, -od      Output only data and disables visual output

    --all-port, -a          Scan all 65535 ports (may take a long time) 


 
Usage:

port-scanner TARGET [-h] [-P] [-p PORTS] [-a] [-t THREADS] [-o] [-ol] [-on] [-od] 

Examples:

port-scanner [IP ADDRESS]

port-scanner [IP ADDRESS] -p "1500"

port-scanner [IP ADDRESS] -t 500 -a

port-scanner [IP ADDRESS] -P -o

port-scanner [IP ADDRESS] -p "80-90" -t 1
