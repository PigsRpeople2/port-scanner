Basic Port Scanner


Flags:
  -h, --help              show help message and exit
  --ports, -p PORTS       The range of ports to scan (e.g., "20-80" or "1000"), default = 10000
  --threads, -t THREADS   Max threads to use, default = 100


example commands:
python3 port-scanner.py [IP ADDRESS]
python3 port-scanner.py [IP ADDRESS] -p "1500"
python3 port-scanner.py [IP ADDRESS] -t 500
python3 port-scanner.py [IP ADDRESS] -p "65535" -t 1000
python3 port-scanner.py [IP ADDRESS] -p "80-90" -t 1
