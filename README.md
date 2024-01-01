# CIDR.SPOOF.SCAN
👽 Unleashes a storm of legitimate looking traffic in order to congest, invalidate, and annoy threat intelligence sensors such as GreyNoise and SpamHaus.

# BUILD
```go build```

# USAGE
```
Scan one IP:
./cidr.spoof.scan -r 1.2.3.4/32

Scan 256 IPs
./cidr.spoof.scan -r 11.22.33.0/24
```

# HELP
```
./cidr.spoof.scan -h
CIDR.SPOOF.SCAN:
    (-r) - CIDR (target) [0.0.0.0/0]
    (-c) - Threads [100]
    (-t) - Duration (seconds) [-1]
    (-u) - Microseconds (μs) delay [0]
```
