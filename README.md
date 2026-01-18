Basic Port Scanner


Flags:

    --help, -h              show help message and exit

    --ports, -p PORTS       The range of ports to scan (e.g., "20-80" or "1000"), default = 10000
  
    --threads, -t THREADS   Max threads to use, default = 100

 
Usage:

port-scanner TARGET [-h] [-P] [-p PORTS] [-a] [-t THREADS] [-o] [-ol] [-on] [-od] 

Examples:

port-scanner [IP ADDRESS]

port-scanner [IP ADDRESS] -p "1500"

port-scanner [IP ADDRESS] -t 500 -a

port-scanner [IP ADDRESS] -P -o

port-scanner [IP ADDRESS] -p "80-90" -t 1
