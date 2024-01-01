# CIDR.SPOOF.SCAN
👽 Unleashes a storm of legitimate looking traffic in order to congest, invalidate, and annoy threat intelligence sensors such as GreyNoise and SpamHaus.

# ☢️ WARNING!
```
REQUIREMENTS FOR THIS TO WORK PROPERLY:
IPHM Enabled Server - Server without BCP38 turned on.

Without this your server will send your server IP and not spoofed IP!
```

# 🚧 BUILD
```go build```

# 🟢 SCANNED PORTS
```
By default it will scan only port 10101.

If you want to change the port edit file main.go at line 34: ports = []int{10101}
If you want to scan multiple ports edit file main.go at line 34: ports = []int{21,22,23}
```

# 💡 USAGE
```
Scan one IP:
./cidr.spoof.scan -r 1.2.3.4/32

Scan 256 IPs:
./cidr.spoof.scan -r 11.22.33.0/24
```

# ❓ HELP
```
./cidr.spoof.scan -h
CIDR.SPOOF.SCAN:
    (-r) - CIDR (target) [0.0.0.0/0]
    (-c) - Threads [100]
    (-t) - Duration (seconds) [-1]
    (-u) - Microseconds (μs) delay [0]
```
