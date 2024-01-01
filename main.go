package main

import (
        "encoding/binary"
        "flag"
        "fmt"
        "math/rand"
        "net"
        "os"
        "os/signal"
        "syscall"
        "time"

        "github.com/google/gopacket"
        "github.com/google/gopacket/layers"
)

var (
        // flags
        cidr     = flag.String("r", "", "CIDR (target)")
        duration = flag.Int("t", -1, "Duration (seconds)")
        workers  = flag.Int("c", 10, "Threads")
        delay    = flag.Int("u", 0, "Microseconds (μs) delay")

        // colors
        colorReset  = "\033[0m"
        colorRed    = "\033[31m"
        colorPurple = "\033[35m"
        colorCyan   = "\033[36m"
        colorGreen   = "\033[32m"
        skull       = "\u2620"

        // target ports
        ports = []int{10101}
)

func winsize(system int) uint16 {
        switch system {
        case 1:
                return 29200 // Linux
        case 2:
                return 5840 // Linux
        case 3:
                return 5720 // Linux
        case 4:
                return 10220 // Linux
        case 5:
                return 14600 // Linux
        case 6:
                return 8192 // Windows
        case 7:
                return 65535 // Windows
        case 8:
                return 65535 // MacOS, FreeBSD
        case 9:
                return 16384 // OpenBSD
        case 10:
                return 4128 // Cisco IOS
        case 11:
                return 32850 // Solaris
        case 12:
                return 49640 // Solaris
        default:
                return 8192
        }
}

func ittl(system int) uint8 {
        switch system {
        case 6:
                return 128 // Windows
        case 7:
                return 128 // Windows
        case 10:
                return 255 // Cisco IOS
        default:
                return 64 // Linux, MacOS, FreeBSD, OpenBSD, Solaris
        }
}

func assemble(daddr, saddr string, dport, sport, system int) ([]byte, error) {
        ip := &layers.IPv4{
                SrcIP:    net.ParseIP(saddr).To4(),
                DstIP:    net.ParseIP(daddr).To4(),
                Version:  4,
                TTL:      ittl(system),
                Protocol: layers.IPProtocolTCP,
        }

        tcp := &layers.TCP{
                SrcPort: layers.TCPPort(sport),
                DstPort: layers.TCPPort(dport),
                Window:  winsize(system),
                Seq:     rand.Uint32(),
                SYN:     true,
        }

        opts := gopacket.SerializeOptions{
                FixLengths:       true,
                ComputeChecksums: true,
        }

        payload := []byte{}
        pl := gopacket.Payload(payload)

        buf := gopacket.NewSerializeBuffer()

        if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
                return nil, err
        }

        if err := gopacket.SerializeLayers(buf, opts, ip, tcp, pl); err != nil {
                return nil, err
        }

        packet := buf.Bytes()
        return packet, nil
}

func rfc1918(ip net.IP) bool {
        _, net0, _ := net.ParseCIDR("0.0.0.0/8")
        _, net10, _ := net.ParseCIDR("10.0.0.0/8")
        _, net192, _ := net.ParseCIDR("192.168.0.0/16")
        _, net172, _ := net.ParseCIDR("172.16.0.0/12")

        if net0.Contains(ip) || net10.Contains(ip) || net192.Contains(ip) || net172.Contains(ip) {
                return true
        }
        return false
}

func sendpacket(fd int, packet []byte, addr string) error {
        ip := net.ParseIP(addr)
        dest := format4(ip)
        if err := syscall.Sendto(fd, packet, 0, &dest); err != nil {
                return err
        }

        return nil
}

func rawsocket() (int, error) {
        handler, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
        if err != nil {
                return -1, err
        }
        return handler, nil
}

func format4(ip net.IP) (addr syscall.SockaddrInet4) {
        addr = syscall.SockaddrInet4{Port: 0}
        copy(addr.Addr[:], ip.To4()[0:4])
        return addr
}

func runCIDR(cidr string, out chan string) error {
        ip, ipnet, err := net.ParseCIDR(cidr)
        if err != nil {
                return err
        }

        for target := ip.Mask(ipnet.Mask); ipnet.Contains(target); inc(target) {
                if rfc1918(target) {
                        continue
                }
                addr, _ := net.ResolveIPAddr("ip", target.String())
                out <- addr.String()
        }
        return nil
}

func inc(ip net.IP) {
        for j := len(ip) - 1; j >= 0; j-- {
                ip[j]++
                if ip[j] > 0 {
                        break
                }
        }
}

func randIP() string {
        for {
                buf := make([]byte, 4)
                ip := rand.Uint32()
                binary.LittleEndian.PutUint32(buf, ip)
                nip := net.IP(buf)
                if !rfc1918(nip) {
                        return nip.String()
                }
        }
}

func thread(addrs chan string) {
        sock, err := rawsocket()
        if err != nil {
                fatal(err)
        }
        defer syscall.Close(sock)
        for addr := range addrs {
                rip := randIP()
                dport := ports[rand.Intn(len(ports))]
                sport := 1024 + rand.Intn(64511)
                syst := 1 + rand.Intn(11)

                pkt, _ := assemble(addr, rip, dport, sport, syst)

                fmt.Printf("[%s%s%s] %s%s:%d%s -> %s%s%s:%s%d%s\n", colorRed, sysident(syst), colorReset, colorCyan, rip, sport, colorReset, colorPurple, addr, colorReset, colorCyan, dport, colorReset)

                sendpacket(sock, pkt, addr)
                time.Sleep(time.Microsecond * time.Duration(*delay))
        }
}

func sysident(id int) string {
        if id >= 1 && id <= 5 {
                return "Linux"
        } else if id >= 6 && id <= 7 {
                return "Windows"
        } else if id == 8 {
                return "MacOS/FreeBSD"
        } else if id == 9 {
                return "OpenBSD"
        } else if id == 10 {
                return "Cisco IOS"
        } else if id >= 11 && id <= 12 {
                return "Solaris"
        } else {
                return "Windows"
        }
}

func banner() {
        fmt.Printf(`%s
 ██▓███   ▄▄▄       ▄████▄   ██ ▄█▀▓█████▄▄▄█████▓ ███▄    █  ▒█████   ██▓  ██████ ▓█████
▓██░  ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀▓  ██▒ ▓▒ ██ ▀█   █ ▒██▒  ██▒▓██▒▒██    ▒ ▓█   ▀
▓██░ ██▓▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███  ▒ ▓██░ ▒░▓██  ▀█ ██▒▒██░  ██▒▒██▒░ ▓██▄   ▒███
▒██▄█▓▒ ▒░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄░ ▓██▓ ░ ▓██▒  ▐▌██▒▒██   ██░░██░  ▒   ██▒▒▓█  ▄
▒██▒ ░  ░ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒ ▒██▒ ░ ▒██░   ▓██░░ ████▓▒░░██░▒██████▒▒░▒████▒
▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░ ▒ ░░   ░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░▓  ▒ ▒▓▒ ▒ ░░░ ▒░ ░
░▒ ░       ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░   ░    ░ ░░   ░ ▒░  ░ ▒ ▒░  ▒ ░░ ░▒  ░ ░ ░ ░  ░
░░         ░   ▒   ░        ░ ░░ ░    ░    ░         ░   ░ ░ ░ ░ ░ ▒   ▒ ░░  ░  ░     ░
               ░  ░░ ░      ░  ░      ░  ░                 ░     ░ ░   ░        ░     ░  ░

%s`, colorGreen, colorReset)
}

func usage() {
        fmt.Fprintf(os.Stderr, `CIDR.SPOOF.SCAN:
    (%s-r%s) - CIDR (target) [%s0.0.0.0/0%s]
    (%s-c%s) - Threads [%s100%s]
    (%s-t%s) - Duration (seconds) [%s-1%s]
    (%s-u%s) - Microseconds (μs) delay [%s0%s]
`, colorCyan, colorReset, colorPurple, colorReset, colorCyan, colorReset, colorPurple, colorReset, colorCyan, colorReset, colorPurple, colorReset, colorCyan, colorReset, colorPurple, colorReset)
}

func fatal(e error) {
        fmt.Printf("%s %s error:%s %s\n", colorRed, skull, colorReset, e)
        os.Exit(-1)
}

func alarm(secs int) {
        time.Sleep(time.Second * time.Duration(secs))
        os.Exit(0)
}

func main() {
        flag.Usage = usage
        flag.Parse()

        var target string
        if *cidr == "" {
                target = "0.0.0.0/0"
        } else {
                target = *cidr
        }

        // signals
        sigs := make(chan os.Signal, 1)
        signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
        go func() {
                <-sigs
                fmt.Printf("\n%s%s Stopped%s\n", colorRed, skull, colorReset)
                os.Exit(1)
        }()

        // threads
        addrs := make(chan string)
        go func() {
                for x := 0; x < *workers; x++ {
                        thread(addrs)
                }
        }()

        // start alarm
        if *duration > 0 {
                go alarm(*duration)
        }

        banner()

        for {
                if e := runCIDR(target, addrs); e != nil {
                        fatal(e)
                }
        }
}
